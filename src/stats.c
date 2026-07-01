#include "stats.h"
#include <stdio.h>

/* ================= 统计变量 ================= */

static unsigned long pkt_total  = 0; //抓到的数据包总个数
static unsigned long pkt_tcp    = 0; //TCP数据包个数
static unsigned long pkt_udp    = 0; //UDP数据包个数
static unsigned long pkt_other  = 0; //非 TCP/UDP 的其他协议数据包个数（如 ICMP、ARP 等）

/* ================= 实现 ================= */

void stats_init(void) {
    stats_clear();
}

void stats_clear(void) {
    pkt_total = 0;
    pkt_tcp   = 0;
    pkt_udp   = 0;
    pkt_other = 0;
}

void stats_record(const struct parsed_packet *pkt) {
    (void)pkt; /* 暂时未使用，抑制警告 */
    pkt_total++;
}

void stats_print(void) {
    printf("Stats: total packets = %lu\n", pkt_total);
}