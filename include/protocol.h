#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

// 协议类型枚举（B负责填充）
enum {
    PROTO_ETH,
    PROTO_IP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_HTTP
};

// 解析后的数据包结构体
struct parsed_packet {
    int proto;          // 协议类型
    size_t payload_len; // 载荷长度
    // 后续B会在这里加更多字段（IP、端口等）
};

// B负责实现的函数：解析原始数据
void parse_packet(const uint8_t *data, size_t len, struct parsed_packet *out);

#endif