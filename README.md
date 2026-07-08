# 项目测试文档

## 功能测试命令

### 1. ICMP 协议解析 + 实时抓包 + BPF 过滤 + 实时统计

对应要求：

- 抓包引擎：`-i ens33`
- 协议解析：Ethernet / IPv4 / ICMP
- BPF 过滤：`-f "icmp"`
- 流量统计：运行过程中每秒刷新，Ctrl+C 后输出最终统计

sniffer 终端：

```bash
sudo ./sniffer -i ens33 -f "icmp"
```

另一个终端：

```bash
ping -c 4 baidu.com
```

观察重点：

```
最上层协议: ICMP
源MAC / 目的MAC
源IP / 目的IP
ICMP packets
```

------

### 2. DNS 协议解析 + UDP 协议解析 + BPF 过滤 + 实时统计

对应要求：

- 抓包引擎：`-i ens33`
- 协议解析：Ethernet / IPv4 / UDP / DNS
- BPF 过滤：`-f "udp port 53"`
- 流量统计：统计 UDP 和 DNS 报文数、字节数

sniffer 终端：

```bash
sudo ./sniffer -i ens33 -f "udp port 53"
```

另一个终端：

```bash
nslookup baidu.com
```

观察重点：

```
最上层协议: DNS
源端口 / 目的端口: 53
UDP packets
DNS packets
```

------

### 3. HTTP 协议解析 + TCP 协议解析 + BPF 过滤 + 实时统计

对应要求：

- 抓包引擎：`-i ens33`
- 协议解析：Ethernet / IPv4 / TCP / HTTP
- BPF 过滤：`-f "tcp port 80"`
- 流量统计：统计 TCP 和 HTTP 报文数、字节数

sniffer 终端：

```bash
sudo ./sniffer -i ens33 -f "tcp port 80"
```

另一个终端：

```bash
wget -O - http://example.com
```

如果没有 `wget`：

```bash
sudo apt install wget
```

观察重点：

```
最上层协议: HTTP 或 TCP
源端口 / 目的端口: 80
TCP packets
HTTP packets
```

------

### 4. 综合流量测试：TCP / UDP / DNS / HTTP 一起验证

对应要求：

- 抓包引擎
- 协议解析：TCP / UDP / DNS / HTTP
- BPF 过滤：排除 SSH 远程连接流量
- 流量统计：多协议统计结果

sniffer 终端：

```bash
sudo ./sniffer -i ens33 -f "not port 22"
```

另一个终端依次执行：

```bash
nslookup baidu.com
wget -O - http://example.com
```

观察重点：

```
TCP packets
UDP packets
HTTP packets
DNS packets
OTHER packets
```

说明：

`not port 22` 用于过滤 VSCode SSH 连接产生的流量，避免测试输出被 SSH 报文干扰。

------

### 5. PCAP 写入 + PCAP 回放测试

对应要求：

- PCAP 写入：`-w`
- PCAP 回放：`-r`
- BPF 过滤：保存 ICMP 流量
- 协议解析：回放时仍能解析 ICMP 报文

第一步，sniffer 终端保存抓包文件：

```bash
sudo ./sniffer -i ens33 -f "icmp" -w icmp.pcap
```

另一个终端制造 ICMP 流量：

```bash
ping -c 4 baidu.com
```

抓包结束后按 `Ctrl+C`，检查文件：

```bash
ls -lh icmp.pcap
```

第二步，回放 pcap 文件：

```bash
./sniffer -r icmp.pcap
```

观察重点：

```
最上层协议: ICMP
Final Traffic Statistics / 最终流量统计
```

------

### 6. 静默性能模式 + 1Gbps 压测

对应要求：

- 抓包引擎：高流量实时抓包
- BPF 过滤：只抓 iperf3 UDP 流量
- 协议解析：UDP 高流量解析
- 流量统计：静默模式下统计报文数和字节数
- 验收标准：1Gbps 流量下丢包率 < 1%，解析正确率 100%

虚拟机1：

终端1启动**抓包程序**：

```bash
sudo ./sniffer -i ens33 -f "udp port 5201" -q
```

另开一个终端2启动 **iperf3 服务端**：

```bash
iperf3 -s
```

虚拟机2运行**客户端**：

```bash
iperf3 -c 192.168.184.131 -u -b 250M -P 4 -t 20
```

等待20秒抓包完毕后终端1结束统计

```bash
ctrl + c
```

观察重点：

```
[SUM] sender   1000 Mbits/sec
[SUM] receiver 993 Mbits/sec
[SUM] UDP loss < 1%

UDP packets
OTHER packets : 0

接收数据包数
丢弃数据包数 : 0
网卡丢包数   : 0
丢包率       : 0.0000%
```

说明：

`-q` 为静默性能模式，只解析和统计，不逐包打印详情，避免终端输出影响高流量抓包性能。



# 项目开发日志

日志更新:zhoulinying

```
首日小组讨论制作需求分析文档，配置开发环境

配置linux虚拟机，搭建ubuntu22.04,使用 Vs Code 作为远程连接客户端

所有代码文件代码、编译，抓包，git管理均在 linux 环境中进行
```

安装开发所需环境：

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev tcpdump tcpreplay wireshark net-tools
```

## 以上命令中每个软件对应选题的用途

| 安装的包            | 是什么                                | 为什么选题7要用                                              |
| ------------------- | ------------------------------------- | ------------------------------------------------------------ |
| **build-essential** | GCC 编译器 + make + binutils          | C17 代码必须用 gcc 编译，没有它连 `.c`都变不成可执行文件     |
| **libpcap-dev**     | libpcap 抓包库的**开发头文件+静态库** | 选题7核心依赖！你的程序 `#include <pcap.h>`并链接 `-lpcap`才能调抓包/BPF/PCAP读写 API |
| **tcpdump**         | 命令行抓包工具（基于 libpcap）        | 用来**验证你程序解析结果对不对**——和你程序抓同一个网卡对比输出 |
| **tcpreplay**       | 把 .pcap 文件"重放"到网卡             | 验收要求测 1Gbps 丢包率/解析正确率，用它可以**回放固定 pcap 复现测试**，不用碰运气抓真实流量 |
| **wireshark**       | 图形化协议分析工具                    | 用来**对照各协议字段**（Ethernet/IP/TCP/DNS/HTTP）写你的解析逻辑，是"标准答案" |
| **net-tools**       | ifconfig 等网络工具                   | 查看虚拟机网卡名（一般是 ens33/eth0），方便指定抓包接口      |

```bash
# 装完做两个快速验证（确认环境 OK）

# 1.确认 libpcap 可用： 有输出（如 -lpcap）就正常。
pcap-config --cflags --libs

# 2.确认能抓包（需要 sudo）：能打印出包说明权限和网卡都正常。
sudo tcpdump -i any -c 5
```



日志更新：zhoulinying
```
开始搭建三个分支
成员A - liuweidong 负责抓包引擎 & PCAP读写模块
成员B - zhenzifeng 负责协议解析模块
成员C - zhoulinying 流程统筹 & 流量统计
```
```
基础接口已开发完毕
接口增强任务：
1. 高流量下丢包率统计
2. TCP 流重组并提取 HTTP 请求/响应对

新增文件
项目结构增加：
include/reassembly.h      // TCP 流重组模块接口，给 B 开发
src/reassembly.c          // TCP 流重组模块空实现/初始实现

修改文件：
include/capture.h         // 增加抓包统计结构体和统计接口，给 A 实现
src/capture.c             // 后续由 A 接入 pcap_stats
main.c                      //加入 include/reassembly.h
Makefile                  // 加入 src/reassembly.c

分工：
B 负责的 TCP 流重组模块，后续就在 reassembly_record() 里实现 TCP seq 排序和 HTTP 请求/响应提取。
include/reassembly.h
src/reassembly.c

A 负责抓包性能统计接口
include/capture.h
src/capture.c
```


# 项目需求分析文档：基于 libpcap 的网络数据包捕获与协议解析工具

## 0.原题描述

```

题目 07  |  网络数据包捕获与协议解析工具
类别：网络安全     难度：★★★☆☆     建议人数：2~3 人

▌ 项目背景
深入理解网络协议栈是网络工程和安全研究的基础。本项目利用 libpcap / Raw Socket 抓取网络数据包，逐层解析以太网、IP、TCP/UDP/ICMP 等协议头，实现一个具备统计、过滤和会话重组功能的轻量级 Wireshark，AI 大模型可辅助解读 RFC 规范和生成协议 Fuzzing 用例。

▌ 功能要求
基础要求（必做）
1.  抓包引擎：基于 libpcap / AF_PACKET Raw Socket，支持网卡混杂模式
2.  协议解析：解析 Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / DNS / HTTP 协议头
3.  BPF 过滤：支持 pcap_compile 过滤规则（如 tcp port 80 and host 192.168.1.1）
4.  流量统计：按协议类型/IP 对实时统计报文数、字节数，每秒刷新显示
5.  PCAP 读写：支持从 .pcap 文件回放，以及将捕获流量写入文件

进阶要求（选做，加分）
A.  TCP 流重组：基于序列号拼接 TCP 载荷，提取完整 HTTP 请求/响应内容
B.  TLS 握手识别：解析 ClientHello / ServerHello，提取 SNI 域名
C.  终端 UI：用 ncurses 实现实时滚动数据包列表和协议树展开界面

▌ AI 辅助建议
💡 请AI解释 TCP 三次握手报文各字段的含义并对应到 C struct 定义
💡 利用AI根据 RFC 793 快速生成 TCP 状态机的 C 语言枚举定义
💡 通过AI设计包含 IP 分片、TCP 乱序的测试 PCAP 文件生成脚本

🔧 核心技术要点	✅ 验收标准
libpcap API、Raw Socket、网络字节序转换、TCP 重组状态机、ncurses	1. 在 1 Gbps 流量下丢包率 < 1%，解析正确率 100%
2. HTTP 流重组能完整提取 5 个以上真实网页请求的请求/响应对
3. 提交协议层次结构图、各协议 C struct 定义文档及性能测试截图
```

## 1. 项目概述

本项目旨在实现一个轻量级的网络协议分析工具（类似简化版 Wireshark）。项目将基于 **C 语言**和 **libpcap** 库，在 Linux 环境下开发。核心目标是深入理解网络协议栈（以太网、IP、TCP/UDP 等）的工作原理，掌握数据包捕获、协议解析、流量统计分析及文件读写等关键系统编程技术。

------

## 2. 技术选型与环境

**开发语言**: C17 标准

**核心库**: libpcap

**开发环境**: Ubuntu 22.04 (VMware)

**协作工具**: GitHub

**IDE**: VS Code (通过 Remote-SSH 连接 Linux)

------

## 3. 需求分析与解决方案

针对题目中的五项基础要求，我们采用以下技术方案：

| 需求点           | 问题分析                                     | 解决方案                                                     |
| ---------------- | -------------------------------------------- | ------------------------------------------------------------ |
| **1. 抓包引擎**  | 如何在内核层面高效捕获经过网卡的数据帧？     | 使用 **libpcap** 库。它提供了统一的 API 接口，能够自动处理底层的套接字细节，并支持将网卡设置为混杂模式（Promiscuous Mode），从而接收所有流经本网卡的数据包。 |
| **2. 协议解析**  | 如何从原始的字节流中提取出有意义的协议字段？ | 定义严格的 **C Struct** 映射协议头。利用 RFC 文档定义 Ethernet、IP、TCP/UDP 等头部结构，特别注意使用 `__attribute__((packed))`防止编译器内存对齐，并使用 `ntohs/ntohl`进行网络字节序到主机字节序的转换。 |
| **3. BPF 过滤**  | 如何在不影响性能的前提下筛选特定流量？       | 使用 libpcap 内置的 **BPF (Berkeley Packet Filter)** 编译器。`pcap_compile()`可将用户输入的字符串规则（如 `tcp port 80`）编译为内核可执行的伪代码，`pcap_setfilter()`将其附加到抓包句柄。 |
| **4. 流量统计**  | 如何实时展示网络状况？                       | 设计 **全局统计结构体**。每当解析完一个数据包，更新对应的计数器（按协议类型、源/目的 IP）。在主循环中利用 `signal`或定时器，每秒刷新一次终端输出。 |
| **5. PCAP 读写** | 如何实现离线分析？                           | 使用 libpcap 的文件 I/O 接口。`pcap_open_offline()`用于读取 `.pcap`文件进行回放；`pcap_dump_open()`结合 `pcap_dump()`用于将实时抓取的包写入文件。 |

------

## 4. 项目开发框架与目录结构

我们将采用模块化设计，目录结构如下。**清晰的目录结构是保证协作顺畅的关键。**

```
sniffer/
├── src/              # 核心业务逻辑 (.c)
│   ├── main.c        # 程序入口、参数解析、主循环
│   ├── capture.c     # 抓包引擎、PCAP读写
│   ├── protocol.c    # 协议解析逻辑
│   └── stats.c       # 流量统计与展示
├── include/          # 头文件 (.h)
│   ├── capture.h
│   ├── protocol.h    # 协议结构体定义
│   └── stats.h
├── tests/            # 测试资源
│   └── *.pcap        # 测试用的数据包文件
├── docs/             # 项目文档
│   ├── report.md     # 实验报告
│   └── ai_logs/      # AI对话截图
├── Makefile          # 构建脚本
└── README.md         # 项目说明
```

------

## 5. 人员分工与开发任务 (A, B, C)

### 进阶增强(更新：2026/7/3)

| 成员 | 角色      | 负责模块                 | 核心任务                                                     | 对应文件                                                   |
| ---- | --------- | ------------------------ | ------------------------------------------------------------ | ---------------------------------------------------------- |
| A    | 底层/性能 | 抓包性能统计 & PCAP 支撑 | 1. 基于 `pcap_stats()` 获取抓包统计信息 2. 统计 `ps_recv / ps_drop / ps_ifdrop` 3. 计算高流量下丢包率 4. 配合性能测试，提供 HTTP 流重组测试用 PCAP 文件 | `src/capture.c` `include/capture.h`                        |
| B    | 逻辑/解析 | TCP 流重组 & HTTP 提取   | 1. 新增 TCP 流重组模块 2. 根据源/目的 IP、端口建立 TCP 流 3. 基于 `tcp_seq` 对 TCP payload 排序和拼接 4. 提取完整 HTTP 请求/响应对 5. 输出 5 个以上真实网页请求/响应内容 | `src/reassembly.c` `include/reassembly.h` `src/protocol.c` |
| C    | 集成/调度 | 主流程集成 & 验收测试    | 1. 搭建进阶模块接口结构 2. 将 `reassembly` 模块加入编译流程 3. 后续在主流程中接入性能统计与流重组调用 4. 组织高流量测试与结果截图 5. 整理最终验收材料 | `src/main.c` `Makefile` `docs/`                            |

```
进阶要求简化版
A 的增强重点：
1. 为 1 Gbps 验收提供抓包统计能力：
   - capture_get_stats()
   - capture_print_stats()
   - pcap_stats()
   - ps_recv / ps_drop / ps_ifdrop / drop_rate

2. 为 HTTP 流重组提供稳定数据来源：
   - 确保实时抓包和 PCAP 回放正常
   - 提供 tcp port 80 的 HTTP 测试 pcap 文件

B 的增强重点：
1. 为 HTTP 流重组验收实现核心逻辑：
   - reassembly_record()
   - TCP flow 管理
   - tcp_seq 排序
   - payload 拼接
   - HTTP 请求/响应对提取

2. 为解析正确率验收配合检查：
   - 确认 TCP seq、ack、flags、payload_len 等字段解析正确
```

```
进阶要求详细版
验收目标1：1 Gbps 流量下丢包率 < 1%，解析正确率 100%
目标1可分成三块：
1.抓包层能统计丢包
2.主流程能跑高性能模式
3.测试阶段能产生高流量并记录结果

A 负责抓包层增强，让程序具备统计丢包率的能力：
A 要做：
1. 在 capture.c 中接入 pcap_stats()
2. 获取 ps_recv、ps_drop、ps_ifdrop
3. 计算 drop_rate
4. 在 capture_print_stats() 中输出抓包统计结果
5. 必要时优化 libpcap 参数，比如 buffer size

C负责：
1. 在 main.c 里调用 capture_print_stats()
2. 增加 quiet 模式，减少逐包打印
3. 用 iperf3 或其他工具做压测
4. 整理截图和丢包率结果

B配合保证：
协议解析在高流量下不要崩
解析字段正确

验收目标2：HTTP 流重组提取 5 个以上请求/响应对
目标2可分成三块：
抓包/PCAP 提供完整 TCP 流
协议解析提供 TCP seq、端口、payload
流重组模块拼接并提取 HTTP

A负责：
1. 确保 capture.c 抓到完整 TCP 包
2. 确保 PCAP 保存和回放正常
3. 提供 http_test.pcap 给 B 离线调试

B负责核心算法，负责真正完成http流重组：
1. 在 reassembly.c 中维护 TCP 流
2. 根据 src/dst IP + src/dst port 区分连接
3. 根据 tcp_seq 对 TCP payload 排序
4. 拼接连续 payload
5. 识别 HTTP 请求和 HTTP 响应
6. 输出请求/响应对到文件

C 后续负责：
1. main.c 接入 reassembly_init()
2. 每个包解析后调用 reassembly_record()
3. 程序结束时调用 reassembly_finish()
4. 整理 5 个 HTTP 请求/响应对截图或输出文件
```



为了保证每人都有足够的代码量且模块间耦合度低，分工如下：

| 成员  | 角色      | 负责模块                | 核心任务                                                     | 对应文件                              |
| ----- | --------- | ----------------------- | ------------------------------------------------------------ | ------------------------------------- |
| **A** | 底层/引擎 | **抓包引擎 & PCAP读写** | 1. 初始化 libpcap 句柄 2. 实现 BPF 过滤设置 3. 实现 Live Capture 回调 4. 实现 PCAP 文件的保存与回放功能 | `src/capture.c` `include/capture.h`   |
| **B** | 逻辑/解析 | **协议解析**            | 1. 定义各层协议头结构体 (Struct) 2. 实现 Ethernet -> IP -> TCP/UDP/ICMP 的逐层解析函数 3. 提取关键字段 (端口、IP、Flags等) 4. 解析 DNS/HTTP 基础字段 | `src/protocol.c` `include/protocol.h` |
| **C** | 集成/调度 | **主流程 & 流量统计**   | 1. 编写 Makefile 2. 实现命令行参数解析 (-i, -f, -r) 3. 实现全局统计逻辑与每秒刷新显示 4. 负责 GitHub 仓库维护与最终集成 | `src/main.c` `src/stats.c` `Makefile` |

------

## 6. 开发流程与时间轴 (总体统筹)

### 第一阶段：基础设施与接口定义 (第1-2天)

**目标**: 搭好架子，定好接口，避免后续冲突。

**行动**:

**C** 初始化 GitHub 仓库，建立上述目录结构，编写基础 Makefile。

**A, B, C** 共同讨论并敲定核心数据结构（特别是 `Packet`结构体，作为 A 和 B 之间的数据交换契约）。

每人创建自己的 `feature-xxx`分支。

### 第二阶段：核心模块并行开发 (第3-8天)

**A**: 专注 libpcap。确保能打开网卡，收到数据，并能把原始数据包传递给处理函数。

**B**: 专注协议。写死一个数据包（Hex dump），验证结构体解析是否正确，对照 Wireshark 检查字段值。

**C**: 搭建主循环，调用 A 的抓包函数，接收 B 的解析结果，实现简单的打印和计数。

**要求**: **每人每天至少 Commit 一次**。Commit 信息要规范（如 `A: Implement pcap live capture callback`）。

### 第三阶段：集成测试与验收 (第9-11天)

**目标**: 合入 `dev`分支，跑通全流程。

**行动**:

使用 `tcpreplay`回放高流量 PCAP 文件，测试丢包率。

对比 Wireshark，验证解析正确率。

修复 Bug，优化性能。

### 第四阶段：文档与交付 (第12-14天)

**C**: 统筹撰写实验报告，整理架构图。

**全员**: 整理 AI 使用记录（截图+说明），准备答辩 Demo。

------

## 7. 协作规范

**禁止直接 Push 到 Main**: 所有功能通过 Pull Request (PR) 合并到 `dev`。

**接口优先**: 修改公共头文件（`.h`）必须通知所有人。

**Commit 频率**: 每天结束工作前必须 Commit，这是老师考核的重要指标。

**AI 使用**: 遇到 RFC 规范不理解、Struct 定义不确定时，使用 AI 辅助，并将对话截图存入 `docs/ai_logs`。

------

## 8. 验收关键点备忘

**丢包率**: 使用 `pcap_stats()`获取统计数据，确保在 1Gbps 回放下 < 1%。

**解析正确性**: 必须能正确解析出 HTTP GET/POST 请求。

**BPF 有效性**: 输入 `tcp port 80`后，不应再看到 443 的包。

请各位成员仔细阅读本文档，并在 GitHub 上确认。如有疑问，立即在群内沟通
