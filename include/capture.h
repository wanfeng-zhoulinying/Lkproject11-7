#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>

// 回调函数类型定义：当有数据包到达时，A会调用这个函数
typedef void (*packet_handler_t)(const uint8_t *data, size_t len);

// 启动抓包的函数声明
void start_capture(const char *device, const char *filter, packet_handler_t handler);

#endif