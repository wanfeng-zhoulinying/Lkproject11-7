#include "reassembly.h"

#include <stdio.h>

static const char *g_output_dir = "http_sessions";
static unsigned long g_tcp_payload_packets = 0;
static unsigned long g_http_sessions = 0;

void reassembly_init(const char *output_dir) {
    if (output_dir && output_dir[0] != '\0') {
        g_output_dir = output_dir;
    }

    g_tcp_payload_packets = 0;
    g_http_sessions = 0;

    printf("[reassembly] output dir: %s\n", g_output_dir);
}

void reassembly_record(const struct parsed_packet *pkt) {
    if (!pkt)
        return;

    if ((pkt->proto == PROTO_TCP || pkt->proto == PROTO_HTTP) &&
        pkt->payload && pkt->payload_len > 0) {
        g_tcp_payload_packets++;

        /*
         * TODO(B):
         * 1. 根据 src/dst IP、src/dst port 建立 TCP 流
         * 2. 根据 tcp_seq 对 payload 排序
         * 3. 拼接连续 TCP payload
         * 4. 提取 HTTP 请求/响应对
         * 5. 输出到 g_output_dir
         */
    }
}

void reassembly_finish(void) {
    printf("[reassembly] TCP payload packets: %lu\n", g_tcp_payload_packets);
    printf("[reassembly] HTTP sessions extracted: %lu\n", g_http_sessions);
}