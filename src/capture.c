/*
 * capture.c —— 抓包引擎
 * 阶段 1：初始化 pcap 句柄，以混杂模式打开网卡。
 *
 */
#include "capture.h"

#include <pcap.h>
#include <stdio.h>

#define SNAP_LEN     65535   /* 单个包最大捕获长度 */
#define READ_TIMEOUT 1000    /* 读超时(ms) */

void start_capture(const char *device, const char *filter, packet_handler_t handler) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = device;
    pcap_if_t *alldevs = NULL;

    (void)filter;   /* 阶段 1 暂不使用，后续提交实现 */
    (void)handler;  /* 阶段 1 暂不回调 */

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

    printf("[capture] 成功以混杂模式打开网卡: %s\n", dev);
    printf("[capture] (阶段 1：句柄初始化完成，尚未开始抓包)\n");

    if (alldevs) pcap_freealldevs(alldevs);
    pcap_close(handle);
}