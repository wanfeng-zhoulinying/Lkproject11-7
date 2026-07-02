/*
 * capture.c
 * 阶段 5：支持从 .pcap 文件离线回放，与实时抓包共用主循环。
 */
#include "capture.h"

#include <pcap.h>
#include <stdio.h>

#define SNAP_LEN     65535   /* 单个包最大捕获长度 */
#define READ_TIMEOUT 1000    /* 读超时(ms) */

/* ---- 模块内部状态 ---- */
static pcap_dumper_t *g_dumper   = NULL;  /* 保存文件句柄(可为空) */
static const char    *g_savefile = NULL;  /* 保存文件名(可为空)   */
static packet_handler_t g_handler = NULL; /* 上层回调            */

void capture_set_savefile(const char *filename) {
    g_savefile = filename;
}

/* libpcap 每收到一个包都会回到这里 */
static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *h,
                          const u_char *bytes) {
    (void)user;
    if (g_dumper) {
        pcap_dump((u_char *)g_dumper, h, bytes);
    }
    if (g_handler) {
        g_handler((const uint8_t *)bytes, (size_t)h->caplen);
    }
}

/* 编译并装载 BPF 过滤规则。filter 为空表示不过滤。 */
static int apply_filter(pcap_t *handle, const char *filter, bpf_u_int32 netmask) {
    struct bpf_program fp;

    if (filter == NULL || filter[0] == '\0') {
        return 0;
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

/* 实时 / 离线 共用的主循环：打开保存文件 -> 抓包 -> 清理 */
static void run_loop(pcap_t *handle, packet_handler_t handler) {
    g_handler = handler;

    if (g_savefile) {
        g_dumper = pcap_dump_open(handle, g_savefile);
        if (!g_dumper) {
            fprintf(stderr, "[capture] 无法创建保存文件 '%s': %s\n",
                    g_savefile, pcap_geterr(handle));
        } else {
            printf("[capture] 抓到的包将保存到: %s\n", g_savefile);
        }
    }

    pcap_loop(handle, -1, pcap_callback, NULL);

    if (g_dumper) {
        pcap_dump_flush(g_dumper);
        pcap_dump_close(g_dumper);
        g_dumper = NULL;
    }
    pcap_close(handle);
    g_handler = NULL;
}

void start_capture(const char *device, const char *filter, packet_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0, mask = 0;
    const char *dev = device;
    pcap_if_t *alldevs = NULL;

    if (dev == NULL || dev[0] == '\0') {
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "[capture] 找不到可用网卡: %s\n", errbuf);
            return;
        }
        dev = alldevs->name;
        printf("[capture] 未指定网卡，自动选择: %s\n", dev);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }

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

    printf("[capture] 开始在 %s 上抓包(混杂模式)...\n", dev);
    run_loop(handle, handler);
    printf("[capture] 抓包结束。\n");
}

void replay_pcap(const char *filename, const char *filter, packet_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[capture] 无法打开 pcap 文件 '%s': %s\n", filename, errbuf);
        return;
    }
    printf("[capture] 回放文件: %s\n", filename);

    /* 离线文件没有网络掩码，传 0 即可 */
    if (apply_filter(handle, filter, 0) == -1) {
        pcap_close(handle);
        return;
    }

    run_loop(handle, handler);
    printf("[capture] 文件回放结束。\n");
}
