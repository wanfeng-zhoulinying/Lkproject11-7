#include "protocol.h"
#include <string.h>
#include <stddef.h>

// ========== 内部协议头结构体（不对外暴露） ==========
#define ETH_HLEN 14
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17
#define IP_PROTO_ICMP  1
#define IP_PROTO_ICMP6 58

typedef struct __attribute__((packed)) {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t type;
} eth_header_t;

typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} ip_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ver_tc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
} ipv6_header_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} tcp_header_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} udp_header_t;

// ========== 核心解析函数（完整分层逻辑） ==========
void parse_packet(const uint8_t *data, size_t len, struct parsed_packet *out) {
    memset(out, 0, sizeof(struct parsed_packet));
    out->proto = PROTO_ETH;
    if (len < ETH_HLEN) return;

    // 1. 以太网层解析
    const eth_header_t *eth = (const eth_header_t *)data;
    memcpy(out->src_mac, eth->src_mac, 6);
    memcpy(out->dst_mac, eth->dest_mac, 6);
    out->eth_type = ntohs(eth->type);
    size_t ip_offset = ETH_HLEN;

    // 2. IPv4层解析
    if (out->eth_type == ETH_TYPE_IPV4) {
        if (len < ip_offset + sizeof(ip_header_t)) return;
        const ip_header_t *ip = (const ip_header_t *)(data + ip_offset);
        uint8_t ip_hlen = (ip->ver_ihl & 0x0F) * 4;

        out->ip_version = 4;
        out->src_ipv4 = ip->src_ip;
        out->dst_ipv4 = ip->dst_ip;
        out->ip_proto = ip->proto;
        out->ip_total_len = ntohs(ip->total_len);
        out->proto = PROTO_IP;

        size_t transport_offset = ip_offset + ip_hlen;
        size_t transport_len = len - transport_offset;

        // 3. 传输层解析
        switch (ip->proto) {
            case IP_PROTO_TCP: {
                if (transport_len < sizeof(tcp_header_t)) return;
                const tcp_header_t *tcp = (const tcp_header_t *)(data + transport_offset);
                uint8_t tcp_hlen = ((tcp->data_off >> 4) & 0x0F) * 4;

                out->src_port = ntohs(tcp->src_port);
                out->dst_port = ntohs(tcp->dst_port);
                out->tcp_seq = ntohl(tcp->seq);
                out->tcp_ack = ntohl(tcp->ack_seq);
                out->tcp_flags = tcp->flags;
                out->proto = PROTO_TCP;

                out->payload = data + transport_offset + tcp_hlen;
                out->payload_len = transport_len - tcp_hlen;
                break;
            }
            case IP_PROTO_UDP: {
                if (transport_len < sizeof(udp_header_t)) return;
                const udp_header_t *udp = (const udp_header_t *)(data + transport_offset);

                out->src_port = ntohs(udp->src_port);
                out->dst_port = ntohs(udp->dst_port);
                out->proto = PROTO_UDP;

                out->payload = data + transport_offset + sizeof(udp_header_t);
                out->payload_len = transport_len - sizeof(udp_header_t);
                break;
            }
            case IP_PROTO_ICMP:
                out->proto = PROTO_ICMP;
                out->payload = data + transport_offset;
                out->payload_len = transport_len;
                break;
            default:
                out->payload = data + transport_offset;
                out->payload_len = transport_len;
                break;
        }
    }
    // 4. IPv6层解析
    else if (out->eth_type == ETH_TYPE_IPV6) {
        if (len < ip_offset + sizeof(ipv6_header_t)) return;
        const ipv6_header_t *ipv6 = (const ipv6_header_t *)(data + ip_offset);

        out->ip_version = 6;
        memcpy(&out->src_ipv6, &ipv6->src_ip, sizeof(struct in6_addr));
        memcpy(&out->dst_ipv6, &ipv6->dst_ip, sizeof(struct in6_addr));
        out->ip_proto = ipv6->next_header;
        out->ip_total_len = ntohs(ipv6->payload_len);
        out->proto = PROTO_IPV6;

        size_t transport_offset = ip_offset + 40;
        size_t transport_len = len - transport_offset;

        switch (ipv6->next_header) {
            case IP_PROTO_TCP: {
                if (transport_len < sizeof(tcp_header_t)) return;
                const tcp_header_t *tcp = (const tcp_header_t *)(data + transport_offset);
                uint8_t tcp_hlen = ((tcp->data_off >> 4) & 0x0F) * 4;

                out->src_port = ntohs(tcp->src_port);
                out->dst_port = ntohs(tcp->dst_port);
                out->tcp_seq = ntohl(tcp->seq);
                out->tcp_ack = ntohl(tcp->ack_seq);
                out->tcp_flags = tcp->flags;
                out->proto = PROTO_TCP;

                out->payload = data + transport_offset + tcp_hlen;
                out->payload_len = transport_len - tcp_hlen;
                break;
            }
            case IP_PROTO_UDP: {
                if (transport_len < sizeof(udp_header_t)) return;
                const udp_header_t *udp = (const udp_header_t *)(data + transport_offset);

                out->src_port = ntohs(udp->src_port);
                out->dst_port = ntohs(udp->dst_port);
                out->proto = PROTO_UDP;

                out->payload = data + transport_offset + sizeof(udp_header_t);
                out->payload_len = transport_len - sizeof(udp_header_t);
                break;
            }
            case IP_PROTO_ICMP6:
                out->proto = PROTO_ICMP;
                out->payload = data + transport_offset;
                out->payload_len = transport_len;
                break;
            default:
                out->payload = data + transport_offset;
                out->payload_len = transport_len;
                break;
        }
    }
}