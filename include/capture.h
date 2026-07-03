#ifndef CAPTURE_H
#define CAPTURE_H
#include <stddef.h>
#include <stdint.h>

// 回调函数类型定义：当有数据包到达时，A会调用这个函数
typedef void (*packet_handler_t)(const uint8_t *data, size_t len);

// 启动抓包的函数声明
void start_capture(const char *device, const char *filter, packet_handler_t handler);

/*
 * 从 .pcap 文件回放（离线抓包）。
 */
void replay_pcap(const char *filename, const char *filter, packet_handler_t handler);

/*
 * 设置保存文件：在 start_capture 之前调用，
 * 之后所有抓到的包都会被写入该 .pcap 文件。传 NULL 关闭保存。
 */
void capture_set_savefile(const char *filename);

/* 停止当前抓包循环 */
void stop_capture(void);


/*************************************/
struct capture_stats {
    unsigned int recv_packets;
    unsigned int drop_packets;
    unsigned int if_drop_packets;
    double drop_rate;
};

/* 获取抓包统计信息，后续由 A 基于 pcap_stats 实现 */
int capture_get_stats(struct capture_stats *stats);

/* 打印抓包统计信息 */
void capture_print_stats(void);
/*************************************/

#endif