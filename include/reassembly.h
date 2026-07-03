#ifndef REASSEMBLY_H
#define REASSEMBLY_H

#include "protocol.h"

/*
 * TCP 流重组模块初始化。
 * output_dir 用于指定 HTTP 请求/响应对输出目录。
 */
void reassembly_init(const char *output_dir);

/*
 * 记录一个已解析的数据包。
 * main.c 在 parse_packet() 后调用该函数。
 */
void reassembly_record(const struct parsed_packet *pkt);

/*
 * 抓包结束后调用，用于刷新文件、释放资源、打印重组统计。
 */
void reassembly_finish(void);

#endif