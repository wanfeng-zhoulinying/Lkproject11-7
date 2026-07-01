#ifndef CAPTURE_H
#define CAPTURE_H
#include <stddef.h>
#include <stdint.h>

// 回调函数类型定义：当有数据包到达时，A会调用这个函数
typedef void (*packet_handler_t)(const uint8_t *data, size_t len);

// 启动抓包的函数声明
void start_capture(const char *device, const char *filter, packet_handler_t handler);

/*
 * 设置保存文件：在 start_capture 之前调用，
 * 之后所有抓到的包都会被写入该 .pcap 文件。传 NULL 关闭保存。
 */
void capture_set_savefile(const char *filename);

#endif