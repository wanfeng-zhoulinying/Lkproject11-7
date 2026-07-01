/*
 * capture.c
 * 阶段 3：支持 BPF 过滤规则
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
    if (g_handler) {
        g_handler((const uint8_t *)bytes, (size_t)h->caplen);
    }
}

/* 编译并装载 BPF 过滤规则。filter 为空表示不过滤。 */
static int apply_filter(pcap_t *handle, const char *filter, bpf_u_int32 netmask) {
    struct bpf_program fp;

    if (filter == NULL || filter[0] == '\0') {
        return 0;  /* 没有过滤需求 */
    }

    if (pcap_compile(handle, &fp, filter, 1 /*optimize*/, netmask) == -1) {
        fprintf(stderr, "[capture] BPF 编译失败 '%s': %s\n",
                filter, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[capture] 设置过滤器失败: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    printf("[capture] 已启用过滤规则: %s\n", filter);
    return 0;
}

void start_capture(const char *device, const char *filter, packet_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0, mask = 0;
    const char *dev = device;
    pcap_if_t *alldevs = NULL;

    /* 没指定网卡则自动选第一块 */
    if (dev == NULL || dev[0] == '\0') {
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "[capture] 找不到可用网卡: %s\n", errbuf);
            return;
        }
        dev = alldevs->name;
        printf("[capture] 未指定网卡，自动选择: %s\n", dev);
    }

    /* 取网络号与掩码（BPF 里 host/net 判断需要） */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;  /* 取不到不致命 */
    }

    /* 打开网卡：第 3 个参数 1 = 混杂模式 */
    pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, READ_TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[capture] 无法打开网卡 '%s': %s\n", dev, errbuf);
        if (alldevs) pcap_freealldevs(alldevs);
        return;
    }
    if (alldevs) pcap_freealldevs(alldevs);

    if (apply_filter(handle, filter, mask) == -1) {
        pcap_close(handle);
        return;
    }

    g_handler = handler;
    printf("[capture] 开始在 %s 上抓包(混杂模式)...\n", dev);

    pcap_loop(handle, -1, pcap_callback, NULL);

    pcap_close(handle);
    g_handler = NULL;
    printf("[capture] 抓包结束。\n");
}
