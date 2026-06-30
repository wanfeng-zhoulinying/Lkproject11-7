/*
 * capture.c
 * 阶段 2：实现实时抓包回调，把原始包转交上层。
 */
#include "capture.h"

#include <pcap.h>
#include <stdio.h>

#define SNAP_LEN     65535   /* 单个包最大捕获长度 */
#define READ_TIMEOUT 1000    /* 读超时(ms) */

/* ---- 模块内部状态 ---- */
static packet_handler_t g_handler = NULL;  /* 上层回调 */

/* libpcap 每收到一个包都会回到这里 */
static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *h,
                          const u_char *bytes) {
    (void)user;
    /* 把原始字节交给上层。
     * 用 caplen（实际抓到的长度），而非 len（线上原始长度）。 */
    if (g_handler) {
        g_handler((const uint8_t *)bytes, (size_t)h->caplen);
    }
}

void start_capture(const char *device, const char *filter, packet_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = device;
    pcap_if_t *alldevs = NULL;

    (void)filter;  /* 阶段 2 暂不使用，后续提交实现 */

    /* 没指定网卡则自动选第一块 */
    if (dev == NULL || dev[0] == '\0') {
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "[capture] 找不到可用网卡: %s\n", errbuf);
            return;
        }
        dev = alldevs->name;
        printf("[capture] 未指定网卡，自动选择: %s\n", dev);
    }

    /* 打开网卡：第 3 个参数 1 = 混杂模式 */
    pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, READ_TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[capture] 无法打开网卡 '%s': %s\n", dev, errbuf);
        if (alldevs) pcap_freealldevs(alldevs);
        return;
    }
    if (alldevs) pcap_freealldevs(alldevs);

    g_handler = handler;
    printf("[capture] 开始在 %s 上抓包(混杂模式)...\n", dev);

    /* count = -1：一直抓，直到出错 */
    pcap_loop(handle, -1, pcap_callback, NULL);

    pcap_close(handle);
    g_handler = NULL;
    printf("[capture] 抓包结束。\n");
}
