#include "protocol.h"
#include <string.h>

// 以太网头基础常量
#define ETH_HLEN 14

// ========== 核心解析函数（框架版） ==========
void parse_packet(const uint8_t *data, size_t len, struct parsed_packet *out) {
    // 初始化输出结构体
    memset(out, 0, sizeof(struct parsed_packet));
    out->proto = PROTO_ETH;

    // 基础长度校验：连以太网头都不完整则直接返回
    if (len < ETH_HLEN) {
        return;
    }

    // 完整解析逻辑将在后续迭代中实现
}