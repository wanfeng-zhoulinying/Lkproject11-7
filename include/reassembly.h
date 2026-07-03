#ifndef REASSEMBLY_H
#define REASSEMBLY_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

/**
 * @brief 初始化TCP流重组模块
 * @note 程序启动时调用1次，完成流表、输出目录等初始化工作
 */
void reassembly_init(void);

/**
 * @brief 录入一个解析完成的TCP数据包，参与流重组
 * @param pkt  协议解析模块输出的结构化数据包
 * @note  每个包解析完成后调用，非TCP包会自动忽略
 */
void reassembly_record(const struct parsed_packet *pkt);

/**
 * @brief 结束流重组，输出所有剩余的HTTP请求响应对，释放内存
 * @note 程序退出前调用1次，完成收尾、资源清理、结果输出
 */
void reassembly_finish(void);

#endif // REASSEMBLY_H