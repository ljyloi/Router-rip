#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool query2(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::list<RoutingTableEntry> routeList;
uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};
const in_addr_t com_addr = 0x090000e0; //组播地址
macaddr_t com_mac;


void findRoute(RipPacket *rip, uint32_t addr) {
  rip->numEntries = 0;
  int cnt = 0;
  for (std::list<RoutingTableEntry>::iterator it = routeList.begin(); it != routeList.end(); it++) {
    if ((it->addr & (1 << it->len)) == (addr & (1 << it->len))) {
      rip->entries[cnt].addr = it->addr;
      rip->entries[cnt].mask = (1 << (uint64_t)it->len) - 1;
      rip->entries[cnt].metric = it->metric;
      rip->entries[cnt].nexthop = it->nexthop;
      cnt++;
    }
  }
  rip->numEntries = cnt;
}

void sendAllRoute(RipPacket *rip, uint32_t addr) {
  rip->numEntries = 0;
  int cnt = 0;
  for (std::list<RoutingTableEntry>::iterator it = routeList.begin(); it != routeList.end(); it++) {
    if ((it->addr & (1 << it->len)) == (addr & (1 << it->len) && it->nexthop != addr)) {
      rip->entries[cnt].addr = it->addr;
      rip->entries[cnt].mask = (1 << (uint64_t)it->len) - 1;
      rip->entries[cnt].metric = it->metric;
      rip->entries[cnt].nexthop = it->nexthop;
      cnt++;
    }
  }
  rip->numEntries = cnt;
}


void updateChecksum(uint8_t *packet) {
    int sum = 0, length;
    length = (packet[0] & 0xf) * 4;
    uint16_t checksum = (((int)packet[10]) << 8) + (int)packet[11];
    packet[10] = 0;
    packet[11] = 0;
    int cnt = 0;
    for (int i = 0; i < length; i += 2) {
        sum += ((int)packet[i] << 8) + (int)packet[i + 1];
        while (sum > 0xffff) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    sum = 0xffff - sum;
    packet[10] = sum >> 8;
    packet[11] = sum & 0xff;
}


void genIphead(uint8_t *buffer, uint16_t totalLength, uint8_t timeToLive, uint8_t protocol, uint32_t src, uint32_t dst) {
  buffer[0] = (4 << 4) | 5;  //V == 4 && IHL == 5
  buffer[1] = 0; //TOS
  buffer[2] = totalLength >> 8;
  buffer[3] = totalLength & 0xff;
  buffer[4] = buffer[5] = buffer[6] = buffer[7] = 0;
  buffer[8] = timeToLive;
  buffer[9] = protocol;
  buffer[10] = buffer[11] = 0;
  buffer[15] = src >> 24; buffer[14] = (src >> 16) & 0xff; buffer[13] = (src >> 8) & 0xff; buffer[12] = src & 0xff;
  buffer[19] = dst >> 24; buffer[18] = (dst >> 16) & 0xff; buffer[17] = (dst >> 8) & 0xff; buffer[16] = dst & 0xff;
  updateChecksum(buffer);
}

void genUdphead(uint8_t *buffer, uint16_t dataLength) {
  buffer[0] = 0x02;
  buffer[1] = 0x08;
  buffer[2] = 0x02;
  buffer[3] = 0x08;
  buffer[4] = (8 + dataLength) >> 8;
  buffer[5] = (8 + dataLength) & 0xff;
  buffer[6] = buffer[7] = 0;
}

void sendMyRoute() {
  // uint32_t rip_len = assemble(&resp, &output[20 + 8]);

}

uint32_t getSrc(uint8_t *packet) {
  return packet[15] << 24 + packet[14] << 16 + packet[13] << 8 + packet[12];
}

uint32_t getDst(uint8_t *packet) {
  return packet[19] << 24 + packet[18] << 16 + packet[17] << 8 + packet[16];
}

uint32_t getLen(uint32_t mask) {
  uint32_t ans = 0;
  while (mask) {
    ans++;
    mask >>= 1;
  }
  return ans;
}


int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  HAL_ArpGetMacAddress(0, com_addr, com_mac);//获得组播的mac地址

  // 0b. Add direct routes
  //添加rip协议的直连路由
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      // send complete routing table to every interface
      //将自身路由表发给每一个接口
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RipPacket resp;
        RipPacket *t = &resp;
        sendAllRoute(t, addrs[i]);
        resp.command = 2;
        uint32_t rip_len = assemble(&resp, &output[20 + 8]);
        genUdphead(&output[20], rip_len);
        genIphead(output + 0, rip_len + 28, 1, 17, addrs[i], com_addr);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, com_mac);
     
      }
      // RIP
      // checksum calculation for ip and udp
      // if you don't want to calculate udp checksum, set it to zero
      // send it back
      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    src_addr = getSrc(packet);
    dst_addr = getDst(packet);
    //从收到的res中将src_addr 和 dst_addr解析出来，注意使用大端序
    // extract src_addr and dst_addr from packet
    // big endian

    // 2. check whether dst is me
    //将目标地址与当前路由器各网口地址进行比较
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    // TODO: Handle rip multicast address(224.0.0.9)?
    //处理组播
    bool dst_is_com = dst_addr == com_addr;


    if (dst_is_me || dst_is_com) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) { //说明是request请求
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          //返回lab中的所有表请求
          if (rip.numEntries != 1 || rip.entries[0].metric != 16) continue;
          RipPacket resp;
          findRoute(&resp, src_addr);
          resp.command = 2;
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          genUdphead(&output[20], rip_len);
          genIphead(output + 0, rip_len + 28, 1, 17, dst_addr, src_addr);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // 发出的request得到回复，对路由表进行更新
          // update routing table
          int cnt = 0;
          RipPacket resp;
          resp.command = 2;
          uint32_t t_nexthop, t_if_index, t_metric;
          for (int i = 0; i < rip.numEntries; i++) {
              rip.entries[i].metric += 1;
              rip.entries[i].nexthop = src_addr;
              RoutingTableEntry entry = {
                .addr = rip.entries[i].addr, // big endian
                .len = getLen(rip.entries[i].mask),        // small endian
                .if_index = if_index,    // small endian
                .nexthop = src_addr,      // big endian, means direct
                .metric = rip.entries[i].metric
              };
              if (query2(rip.entries[i].addr, &t_nexthop, &t_if_index, &t_metric)) {    
                if (rip.entries[i].metric > 16) {
                  update(false, entry);
                  resp.entries[cnt] = rip.entries[i];
                  resp.entries[cnt].metric = 16;
                  cnt++;
                }
                else if (t_metric > rip.entries[i].metric){
                  update(true, entry);
                  resp.entries[cnt] = rip.entries[i];
                  cnt++;
                }
              }
              else {
                update(true, entry);
              }
          }
          if (cnt != 0) {
            resp.numEntries = cnt;
            uint32_t rip_len = assemble(&resp, &output[20 + 8]);
            for (int i = 0; i < N_IFACE_ON_BOARD; i++) 
              if (i != if_index) {
                genUdphead(&output[20], rip_len);
                genIphead(output + 0, rip_len + 28, 1, 17, addrs[i], com_addr);
                HAL_SendIPPacket(i, output, rip_len + 20 + 8, com_mac);
              }
          // for (int i = 0; i < rip.numEntries; i++) {
          //   if (rip.entries[i].metric + 1 > 16)
          //     update(0, rip.entries[i]);
          // }
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      // 转发操作
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          if (forward(output, res))
          // TODO: you might want to check ttl=0 case
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}

