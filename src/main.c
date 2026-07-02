/*
 * test_capture.c —— 成员 A 的独立自测程序
 *
 * 不依赖 B 的解析和 C 的统计，单独验证抓包引擎是否工作。
 * 用法：
 4 类参数组合	-i 实时 / -r 回放 / -f 过滤 / -w 保存
# 实时抓包

sudo ./sniffer -i ens33

sudo ./sniffer -i ens33 -f "tcp port 80"

sudo ./sniffer -i ens33 -f "tcp" -w cap.pcap

sudo tcpdump -i lo

# 回放(无需 root)

./sniffer -r cap.pcap

./sniffer -r cap.pcap -f "udp"


# 回放时另存
./sniffer -r cap.pcap -w copy.pcap

ls -l cap.pcap copy.pcap        # 两个文件大小应该一致
 */
#include <stdio.h>
#include <string.h>
#include "capture.h"

static unsigned long g_count = 0;

/* 充当上层回调：把 A 抓到的每个包打印出来 */
static void on_packet(const uint8_t *data, size_t len) {
    g_count++;
    printf("[#%lu] 收到数据包，长度=%zu 字节，首字节=%02x:%02x:%02x...\n",
           g_count, len,
           len > 0 ? data[0] : 0,
           len > 1 ? data[1] : 0,
           len > 2 ? data[2] : 0);
}

int main(int argc, char *argv[]) {
    const char *dev = NULL, *filter = NULL, *readfile = NULL, *savefile = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) dev = argv[++i];
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) filter = argv[++i];
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) readfile = argv[++i];
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) savefile = argv[++i];
        else {
            fprintf(stderr, "未知参数: %s\n", argv[i]);
            return 1;
        }
    }

    if (savefile) capture_set_savefile(savefile);

    if (readfile) {
        replay_pcap(readfile, filter, on_packet);
    } else {
        start_capture(dev, filter, on_packet);
    }

    printf("===== 本次共处理 %lu 个数据包 =====\n", g_count);
    return 0;
}
