#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>

// 协议类型枚举
enum {
    PROTO_ETH,
    PROTO_IP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_HTTP,
    PROTO_IPV6,
    PROTO_ICMP,
    PROTO_DNS
};

// 解析后的数据包结构体
struct parsed_packet {
    int proto;          // 最上层协议类型
    size_t payload_len; // 载荷长度
    // 以太网层
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t eth_type;

    // IP层（IPv4/IPv6通用）
    uint8_t ip_version;     // 4或6
    struct in_addr src_ipv4;
    struct in_addr dst_ipv4;
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    uint8_t ip_proto;       // 上层协议号
    uint16_t ip_total_len;

    // 传输层
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_flags;

    // 载荷起始指针
    const uint8_t *payload;
};

// 解析原始数据
void parse_packet(const uint8_t *data, size_t len, struct parsed_packet *out);

// 辅助调试函数：打印解析结果（调试用，不影响其他模块）
void print_parsed_packet(const struct parsed_packet *pkt);

#endif // PROTOCOL_H