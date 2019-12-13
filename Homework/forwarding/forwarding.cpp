#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  int sum = 0, length;
  length = (packet[0] & 0xf) * 4;
  uint16_t checksum = (((int)packet[10]) << 8) + (int)packet[11];
  packet[10] = 0;
  packet[11] = 0;
  for (int i = 0; i < length; i += 2) {
      sum += ((int)packet[i] << 8) + (int)packet[i + 1];
      while (sum > 0xffff) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
  }
  sum = 0xffff - sum;
  if (sum != checksum) return false;
  packet[8]--;
  if (!packet[8]) return false;
  sum = 0;
  for (int i = 0; i < length; i += 2) {
      sum += ((int)packet[i] << 8) + (int)packet[i + 1];
      while (sum > 0xffff) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
  }
  sum = 0xffff - sum;
  packet[10] = sum >> 8;
  packet[11] = sum & 0xff;
  return true;
}