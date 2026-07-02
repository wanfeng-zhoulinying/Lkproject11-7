#ifndef STATS_H
#define STATS_H

#include "protocol.h"

// 初始化统计模块
void stats_init(void);

// 记录一个数据包（C负责在里面计数）
void stats_record(const struct parsed_packet *pkt);

// 打印统计结果
void stats_print(void);

/* 清零统计（可选，调试用） */
void stats_clear(void);

#endif