/*
 * capture.c
 * 阶段 4：抓到的包写入 .pcap 文件。
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

    /* 1) 若开启了保存，原样写入 pcap 文件 */
    if (g_dumper) {
        pcap_dump((u_char *)g_dumper, h, bytes);
    }

    /* 2) 把原始字节交给上层（B 解析 / C 统计） */
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

    /* 需要保存时，按句柄的链路类型创建 dumper */
    if (g_savefile) {
        g_dumper = pcap_dump_open(handle, g_savefile);
        if (!g_dumper) {
            fprintf(stderr, "[capture] 无法创建保存文件 '%s': %s\n",
                    g_savefile, pcap_geterr(handle));
        } else {
            printf("[capture] 抓到的包将保存到: %s\n", g_savefile);
        }
    }

    g_handler = handler;
    printf("[capture] 开始在 %s 上抓包(混杂模式)...\n", dev);

    pcap_loop(handle, -1, pcap_callback, NULL);

    if (g_dumper) {
        pcap_dump_flush(g_dumper);
        pcap_dump_close(g_dumper);
        g_dumper = NULL;
    }
    pcap_close(handle);
    g_handler = NULL;
    printf("[capture] 抓包结束。\n");
}
