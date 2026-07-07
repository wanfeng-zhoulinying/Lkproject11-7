/*
 * capture.c
 */
#include "capture.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SNAP_LEN     65535   /* 单个包最大捕获长度，足够抓全整包 */
#define READ_TIMEOUT 1000    /* 读超时(ms) */
#define PCAP_BUFFER_SIZE (64 * 1024 * 1024)  /* 64MB 抓包缓冲区 */

static struct capture_stats g_last_stats;
static int g_has_stats = 0;

/* ---- 模块内部状态 ---- */
static pcap_t        *g_handle  = NULL;  /* 当前 pcap 句柄        */
static pcap_dumper_t *g_dumper  = NULL;  /* 保存文件句柄(可为空)  */
static const char    *g_savefile = NULL; /* 保存文件名(可为空)    */
static packet_handler_t g_handler = NULL;/* 上层回调              */

/* ====================== 对外的小工具函数 ====================== */

void capture_set_savefile(const char *filename) {
    g_savefile = filename;
}

void stop_capture(void) {
    if (g_handle) {
        pcap_breakloop(g_handle);  /* 让 pcap_loop 尽快返回 */
    }
}

/* SIGINT(Ctrl+C) 处理：跳出抓包循环 */
static void on_sigint(int sig) {
    (void)sig;
    stop_capture();
}

/* ====================== 核心抓包逻辑 ====================== */

/* libpcap 每收到一个包都会回到这里 */
static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *h,
                          const u_char *bytes) {
    (void)user;

    /* 1) 若开启了保存，原样写入 pcap 文件 */
    if (g_dumper) {
        pcap_dump((u_char *)g_dumper, h, bytes);
    }

    /* 2) 把原始字节交给上层。
     *    用 caplen（实际抓到的长度），而不是 len（线上原始长度）。 */
    if (g_handler) {
        g_handler((const uint8_t *)bytes, (size_t)h->caplen);
    }
}

static int update_capture_stats(pcap_t *handle) {
    struct pcap_stat ps;

    if (!handle)
        return -1;

    if (pcap_stats(handle, &ps) == -1) {
        return -1;
    }

    g_last_stats.recv_packets = ps.ps_recv;
    g_last_stats.drop_packets = ps.ps_drop;
    g_last_stats.if_drop_packets = ps.ps_ifdrop;

    unsigned int total = ps.ps_recv + ps.ps_drop;
    g_last_stats.drop_rate = total > 0 ? (double)ps.ps_drop / total : 0.0;

    g_has_stats = 1;
    return 0;
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

static pcap_t *open_live_handle(const char *dev, char *errbuf) {
    pcap_t *handle = pcap_create(dev, errbuf);
    if (!handle)
        return NULL;

    pcap_set_snaplen(handle, SNAP_LEN);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, READ_TIMEOUT);

    if (pcap_set_buffer_size(handle, PCAP_BUFFER_SIZE) != 0) {
        fprintf(stderr, "[capture] 警告: 设置抓包缓冲区失败，继续使用默认缓冲区\n");
    }

    int ret = pcap_activate(handle);
    if (ret < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (ret > 0) {
        fprintf(stderr, "[capture] 警告: %s\n", pcap_statustostr(ret));
    }

    return handle;
}

/* 实时 / 离线 共用的主循环：打开保存文件 -> 抓包 -> 清理 */
static void run_loop(pcap_t *handle, packet_handler_t handler) {
    g_handle  = handle;
    g_handler = handler;

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

    /* count = -1：一直抓，直到出错 / 文件读完 / breakloop */
    pcap_loop(handle, -1, pcap_callback, NULL);

    /* 关闭句柄前读取 libpcap 统计信息 */
    update_capture_stats(handle);

    /* 收尾，释放资源 */
    if (g_dumper) {
        pcap_dump_flush(g_dumper);
        pcap_dump_close(g_dumper);
        g_dumper = NULL;
    }
    pcap_close(handle);
    g_handle  = NULL;
    g_handler = NULL;
}

/* ====================== 实时抓包 ====================== */

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

    /* 取网络号与掩码（BPF 过滤里 host/net 判断需要） */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;  /* 取不到不致命，过滤里没用到 net 即可 */
    }

    /* 打开网卡：第 3 个参数 1 = 混杂模式 */
    pcap_t *handle = open_live_handle(dev, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[capture] 无法打开网卡 '%s': %s\n", dev, errbuf);
        if (alldevs) pcap_freealldevs(alldevs);
        return;
    }
    if (alldevs) pcap_freealldevs(alldevs);  /* dev 名已被 libpcap 内部复制，可安全释放 */

    printf("[capture] 开始在 %s 上抓包(混杂模式)... 按 Ctrl+C 停止\n", dev);
    signal(SIGINT, on_sigint);

    if (apply_filter(handle, filter, mask) == -1) {
        pcap_close(handle);
        return;
    }

    run_loop(handle, handler);
    printf("[capture] 抓包结束。\n");
}

/* ====================== PCAP 文件回放 ====================== */

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

int capture_get_stats(struct capture_stats *stats) {
    if (!stats)
        return -1;

    if (g_handle && update_capture_stats(g_handle) == 0) {
        *stats = g_last_stats;
        return 0;
    }

    if (g_has_stats) {
        *stats = g_last_stats;
        return 0;
    }

    return -1;
}

void capture_print_stats(void) {
    struct capture_stats stats;

    if (capture_get_stats(&stats) != 0) {
        printf("[capture] 当前无可用抓包性能统计信息。\n");
        return;
    }

    printf("==============================================\n");
    printf("              抓包性能统计                    \n");
    printf("==============================================\n");
    printf(" 接收数据包数 : %u\n", stats.recv_packets);
    printf(" 丢弃数据包数 : %u\n", stats.drop_packets);
    printf(" 网卡丢包数   : %u\n", stats.if_drop_packets);
    printf(" 丢包率       : %.4f%%\n", stats.drop_rate * 100.0);
    printf("==============================================\n");
}
