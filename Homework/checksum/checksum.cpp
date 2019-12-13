#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
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
    if (sum == checksum) return true;
    return false;   
}