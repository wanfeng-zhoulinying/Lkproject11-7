/*
 * A 部分抓包测试
 *
 * 不依赖 B 的解析和 C 的统计，单独验证抓包引擎是否工作。
 * 用法：
 * 4 类参数组合	-i 实时 / -r 回放 / -f 过滤 / -w 保存
 *
 * # 实时抓包
 * sudo ./sniffer -i ens33
 * sudo ./sniffer -i ens33 -f "tcp port 80"
 * sudo ./sniffer -i ens33 -f "tcp" -w cap.pcap
 * sudo tcpdump -i lo
 *
 * # 回放(无需 root)
 * ./sniffer -r cap.pcap
 * ./sniffer -r cap.pcap -f "udp"
 *
 * # 回放时另存
 * ./sniffer -r cap.pcap -w copy.pcap
 * ls -l cap.pcap copy.pcap        # 两个文件大小应该一致
 */
 
/* 
实时抓包 + 混杂模式
sudo ./sniffer -i ens33 -f "not port 22"

ICMP 解析和统计
sudo ./sniffer -i ens33 -f "icmp"
ping -c 4 baidu.com

DNS 解析和统计
sudo ./sniffer -i ens33 -f "udp or port 53"
nslookup baidu.com

HTTP 解析和统计
sudo ./sniffer -i ens33 -f "tcp port 80"
curl http://example.com

PCAP 写入
sudo ./sniffer -i ens33 -f "icmp" -w icmp.pcap
ping -c 4 baidu.com
停止后检查：
ls -lh icmp.pcap

展示 PCAP 回放
./sniffer -r icmp.pcap
展示带过滤回放：
./sniffer -r icmp.pcap -f "icmp" */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "capture.h"
#include "protocol.h"
#include "stats.h"
#include "reassembly.h"

static volatile sig_atomic_t running = 1;
static int quiet_mode = 0;
static int enable_reassembly = 0;
static const char *reassembly_output_dir = "http_sessions";

/* Ctrl+C 退出 */
static void on_sigint(int sig) {
    (void)sig;
    running = 0;
    stop_capture();
}

/* 充当上层回调：A 抓包 → B 解析 → C 统计 */
static void on_packet(const uint8_t *data, size_t len) {
    struct parsed_packet pkt;

    /* B：协议解析 */
    parse_packet(data, len, &pkt);
    print_parsed_packet(&pkt);

    /* C：统计记录 */
    stats_record(&pkt);

    /* C：每秒刷新一次统计信息 */
    static time_t last_print = 0;
    time_t now = time(NULL);
    if (now != last_print) {
        stats_print();
        last_print = now;
    }

    /* A：原始字节信息（保留，便于对照链路层差异） */
    static unsigned long g_count = 0;
    g_count++;
    printf("[#%lu] 收到数据包，长度=%zu 字节，首字节=%02x:%02x:%02x...\n",
           g_count, len,
           len > 0 ? data[0] : 0,
           len > 1 ? data[1] : 0,
           len > 2 ? data[2] : 0);
}

int main(int argc, char *argv[]) {
    const char *dev = NULL, *filter = NULL, *readfile = NULL, *savefile = NULL;

    /* ---------- A 的参数解析（完全不变） ---------- */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            dev = argv[++i];
        } else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            filter = argv[++i];
        } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            readfile = argv[++i];
        } else if (!strcmp(argv[i], "-w") && i + 1 < argc) {
            savefile = argv[++i];
        } else {
            fprintf(stderr,
                "用法: %s [-i 网卡] [-r pcap文件] [-f 过滤规则] [-w 保存文件]\n",
                argv[0]);
            return 1;
        }
    }

    /* ---------- C：初始化统计模块 ---------- */
    stats_init();

    /* ---------- A：保存 pcap（可选） ---------- */
    if (savefile) {
        capture_set_savefile(savefile);
    }

    signal(SIGINT, on_sigint);
    printf("Sniffer started. Press Ctrl+C to stop.\n");

    /* ---------- A：启动抓包 / 回放 ---------- */
    if (readfile) {
        replay_pcap(readfile, filter, on_packet);
    } else {
        if (!dev) {
            fprintf(stderr, "错误：实时抓包必须指定 -i 网卡\n");
            return 1;
        }
        start_capture(dev, filter, on_packet);
    }

    /* ---------- C：退出后打印最终统计 ---------- */
    printf("\n===== 最终流量统计 =====\n");
    stats_print();

    return 0;
}