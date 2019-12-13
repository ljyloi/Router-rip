#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
uint32_t num4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return ((uint32_t)a << 24) + ((uint32_t)b << 16) + ((uint32_t)c << 8) + d;
}

uint16_t num2(uint8_t a, uint8_t b) {
  return ((uint16_t)a << 8) + b;
}

bool illegal(uint32_t a) {
  int no = 0;
  for (int i = 31; i >= 0; i--) {
    if ((a >> i) & 1) {
      if (no) return true;
    }
    else no = 1;
  }
  return false;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  int totalLength = num2(packet[2], packet[3]);
  if (totalLength > len) return false;
  // TODO:
  int headLength = (packet[0] & 0xf) * 4;
  int command = packet[headLength + 8];
  if (command != 1 && command != 2) return false;
  int familyShouldBe = command == 1 ? 0 : 2;
  int version = packet[headLength + 9];
  if (version != 2) return false;
  int zero = (packet[headLength + 10] << 8) + packet[headLength + 11];
  if (zero != 0) return false;
  for (int i = headLength + 12; i < totalLength; i += 20) {
    int family = (packet[i] << 8) + packet[i + 1];
    if (family != familyShouldBe) return false;
    int tag = (packet[i + 2] << 8) + packet[i + 3];
    if (tag != 0) return false;
    
    uint32_t address = num4(packet[i + 4], packet[i + 5], packet[i + 6], packet[i + 7]);
    uint32_t mask = num4(packet[i + 8], packet[i + 9], packet[i + 10], packet[i + 11]);
    uint32_t nextHop = num4(packet[i + 12], packet[i + 13], packet[i + 14], packet[i + 15]);
    uint32_t metric = num4(packet[i + 16], packet[i + 17], packet[i + 18], packet[i + 19]);
    if (illegal(mask)) return false;
    if (!(metric >= 1 && metric <= 16)) return false;
  }
  output->command = command;
  output->numEntries = (totalLength - headLength - 4) / 20;
  int cnt = 0;
  for (int i = headLength + 12; i < totalLength; i += 20) {
    uint32_t address = num4(packet[i + 7], packet[i + 6], packet[i + 5], packet[i + 4]);
    uint32_t mask = num4(packet[i + 11], packet[i + 10], packet[i + 9], packet[i + 8]);
    uint32_t nextHop = num4(packet[i + 15], packet[i + 14], packet[i + 13], packet[i + 12]);
    uint32_t metric = num4(packet[i + 19], packet[i + 18], packet[i + 17], packet[i + 16]);
    output->entries[cnt].addr = address;
    output->entries[cnt].mask = mask;
    output->entries[cnt].nexthop = nextHop;
    output->entries[cnt].metric = metric;
    cnt++;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 0x0002;
  buffer[2] = buffer[3] = 0;
  for (int i = 0; i < rip->numEntries; i++) {
    int head = i * 20 + 4;
    buffer[head] = 0;
    buffer[head + 1] = buffer[0] == 1 ? 0 : 2;
    buffer[head + 2]  = buffer[head + 3] = 0;
    uint32_t addr = rip->entries[i].addr;
    uint32_t mask = rip->entries[i].mask;
    uint32_t hop = rip->entries[i].nexthop;
    uint32_t metric = rip->entries[i].metric;
    buffer[head + 7] = addr >> 24; buffer[head + 6] = addr >> 16 & 0xff; buffer[head + 5] = addr >> 8 & 0xff; buffer[head + 4] = addr & 0xff;
    buffer[head + 11] = mask >> 24; buffer[head + 10] = mask >> 16 & 0xff; buffer[head + 9] = mask >> 8 & 0xff; buffer[head + 8] = mask & 0xff;
    buffer[head + 15] = hop >> 24; buffer[head + 14] = hop >> 16 & 0xff; buffer[head + 13] = hop >> 8 & 0xff; buffer[head + 12] = hop & 0xff;
    buffer[head + 19] = metric >> 24; buffer[head + 18] = metric >> 16 & 0xff; buffer[head + 17] = metric >> 8 & 0xff; buffer[head + 16] = metric & 0xff;
  }
  return rip->numEntries * 20 + 4;
}