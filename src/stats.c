#include "stats.h"
#include <stdio.h>

/* ================= 统计变量 ================= */

static unsigned long pkt_total  = 0; //抓到的数据包总个数
static unsigned long byte_total  = 0; //数据总字节数（含载荷）

static unsigned long pkt_tcp    = 0; //TCP数据包个数
static unsigned long pkt_udp    = 0; //UDP数据包个数
static unsigned long pkt_icmp   = 0; //ICMP数据包个数
static unsigned long pkt_http   = 0; //HTTP数据包个数
static unsigned long pkt_dns    = 0; //DNS数据包个数
static unsigned long pkt_other  = 0; //其他协议数据包个数（非 TCP/UDP/ICMP）

static unsigned long bytes_tcp   = 0; //TCP数据包字节数
static unsigned long bytes_udp   = 0; //UDP数据包字节数
static unsigned long bytes_icmp  = 0; //ICMP数据包字节数
static unsigned long bytes_http  = 0; //HTTP数据包字节数
static unsigned long bytes_dns   = 0; //DNS数据包字节数
static unsigned long bytes_other = 0; //其他协议数据包字节数

/* IP 协议号，用于按传输层统计 */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ICMP6  58

/* ================= 实现 ================= */

void stats_init(void) {
    stats_clear();
}

void stats_clear(void) {
    pkt_total = 0;
    byte_total = 0;

    pkt_tcp   = 0;
    pkt_udp   = 0;
    pkt_icmp  = 0;
    pkt_http  = 0;
    pkt_dns   = 0;
    pkt_other = 0;

    bytes_tcp   = 0;
    bytes_udp   = 0;
    bytes_icmp  = 0;
    bytes_http  = 0;
    bytes_dns   = 0;
    bytes_other = 0;
}

void stats_record(const struct parsed_packet *pkt) {
    if (!pkt)
        return;

    pkt_total++;
    byte_total += pkt->payload_len;

    /*
     * 传输层统计：
     * HTTP 属于 TCP，DNS 通常属于 UDP。
     * 因此这里优先根据 ip_proto 统计 TCP/UDP/ICMP，
     * 避免 HTTP/DNS 被 proto 覆盖后误算到 OTHER。
     */
    switch (pkt->ip_proto) {
        case IP_PROTO_TCP:
            pkt_tcp++;
            bytes_tcp += pkt->payload_len;
            break;
        case IP_PROTO_UDP:
            pkt_udp++;
            bytes_udp += pkt->payload_len;
            break;
        case IP_PROTO_ICMP:
        case IP_PROTO_ICMP6:
            pkt_icmp++;
            bytes_icmp += pkt->payload_len;
            break;
        default:
            pkt_other++;
            bytes_other += pkt->payload_len;
            break;
    }

    /*
     * 应用层统计：
     * 在传输层统计基础上，额外统计 HTTP / DNS。
     */
    switch (pkt->proto) {
        case PROTO_HTTP:
            pkt_http++;
            bytes_http += pkt->payload_len;
            break;
        case PROTO_DNS:
            pkt_dns++;
            bytes_dns += pkt->payload_len;
            break;
        default:
            break;
    }
}

void stats_print(void) {
    printf("\033[2J\033[H");  //终端清屏

    printf("==============================================\n");
    printf("           SNIFFER TRAFFIC STATS              \n");
    printf("==============================================\n");
    printf(" Total packets : %-10lu\n", pkt_total);
    printf(" Total bytes   : %-10lu\n", byte_total);
    printf("----------------------------------------------\n");
    printf(" TCP packets   : %-10lu (bytes: %lu)\n", pkt_tcp,  bytes_tcp);
    printf(" UDP packets   : %-10lu (bytes: %lu)\n", pkt_udp,  bytes_udp);
    printf(" ICMP packets  : %-10lu (bytes: %lu)\n", pkt_icmp, bytes_icmp);
    printf(" HTTP packets  : %-10lu (bytes: %lu)\n", pkt_http, bytes_http);
    printf(" DNS packets   : %-10lu (bytes: %lu)\n", pkt_dns,  bytes_dns);
    printf(" OTHER packets : %-10lu (bytes: %lu)\n", pkt_other, bytes_other);
    printf("==============================================\n");
}