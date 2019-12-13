#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <list>
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
int cnt;
std::list<RoutingTableEntry> routeList;
void update(bool insert, RoutingTableEntry entry) {
  for (std::list<RoutingTableEntry>::iterator it = routeList.begin(); it != routeList.end(); it++) {
    if (it->addr == entry.addr && it->len == entry.len) {
      if (insert) {
        it->if_index = entry.if_index;
        it->nexthop = entry.nexthop;
        it->metric = entry.metric;
        return;
      }
      routeList.erase(it);
      return;
      
    }
  }  // TODO:
  if (insert)
    routeList.push_back(entry);
}


int match(uint32_t a, uint32_t b) {
  for (int i = 1; i <= 4; i++) {
    if ((a & (0xff << (8 * i - 8))) != (b & (0xff << (8 * i - 8))))
      return i - 1;
  }
  return 4;
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  RoutingTableEntry *best;
  int length = 0;
  for (std::list<RoutingTableEntry>::iterator it = routeList.begin(); it != routeList.end(); it++) {
    int l = match(it->addr, addr);
    if (l > length && it->len <= l * 8) {
      length = l;
      *nexthop = it->nexthop;
      *if_index = it->if_index;
    }
  }  // TODO:i
  if (length == 0)
    return false;
  return true;
}

bool query2(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  RoutingTableEntry *best;
  int length = 0;
  for (std::list<RoutingTableEntry>::iterator it = routeList.begin(); it != routeList.end(); it++) {
    int l = match(it->addr, addr);
    if (l > length && it->len <= l * 8) {
      length = l;
      *nexthop = it->nexthop;
      *if_index = it->if_index;
      *metric = it->metric;
    }
  }  // TODO:i
  if (length == 0)
    return false;
  return true;
}