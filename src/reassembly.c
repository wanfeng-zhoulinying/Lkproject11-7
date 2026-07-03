#include "reassembly.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

// ===================== 内部宏定义 =====================
#define HTTP_OUTPUT_DIR "./http_output/"  // HTTP结果输出目录
#define MAX_HTTP_BODY_SIZE 1024 * 1024   // 单条HTTP最大拼接长度，防止内存溢出

// ===================== 内部数据结构 =====================
/**
 * @brief TCP报文片段节点
 * 按tcp_seq排序，存储单个TCP包的载荷数据
 */
typedef struct tcp_segment {
    uint32_t seq;                // 该片段的起始序列号
    size_t len;                   // 载荷长度
    uint8_t *payload;             // 载荷数据拷贝
    struct tcp_segment *next;     // 链表下一个节点
} tcp_segment_t;

/**
 * @brief TCP双向流结构体
 * 一个五元组对应一条完整TCP连接，分两个方向存储报文片段
 */
typedef struct tcp_stream {
    // 五元组标识（区分IPv4/IPv6）
    uint8_t ip_version;           // 4 or 6
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } src_ip;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    // 双向报文片段链表：客户端→服务端 / 服务端→客户端
    tcp_segment_t *client_to_server;
    tcp_segment_t *server_to_client;

    // 已拼接完成的连续缓冲区（后续填充）
    uint8_t *c2s_buf;
    size_t c2s_buf_len;
    uint8_t *s2c_buf;
    size_t s2c_buf_len;

    struct tcp_stream *next;      // 流表链表下一个节点
} tcp_stream_t;

// ===================== 全局变量：流表头 =====================
static tcp_stream_t *stream_table = NULL;
static int http_pair_count = 0;   // 已输出的HTTP请求响应对计数

// ===================== 内部辅助函数声明 =====================
/**
 * @brief 根据五元组查找对应TCP流，找不到返回NULL
 */
static tcp_stream_t* find_stream(const struct parsed_packet *pkt);

/**
 * @brief 新建一条TCP流并插入流表头部
 */
static tcp_stream_t* create_stream(const struct parsed_packet *pkt);

/**
 * @brief 将TCP片段按seq升序插入对应方向的链表
 * @param head  目标方向的片段链表头
 * @param seq   片段起始序列号
 * @param payload 载荷数据指针
 * @param len   载荷长度
 */
static void insert_segment(tcp_segment_t **head, uint32_t seq, const uint8_t *payload, size_t len);

/**
 * @brief 拼接链表中连续的TCP片段，合并到完整缓冲区
 * @param head  片段链表头
 * @param buf   目标拼接缓冲区
 * @param buf_len 缓冲区当前长度
 */
static void merge_contiguous_segments(tcp_segment_t **head, uint8_t **buf, size_t *buf_len);

/**
 * @brief 从拼接完成的缓冲区中，识别并提取HTTP请求/响应对
 * @param request_buf  请求方向缓冲区
 * @param request_len  请求缓冲区长度
 * @param response_buf 响应方向缓冲区
 * @param response_len 响应缓冲区长度
 */
static void extract_http_pairs(uint8_t *request_buf, size_t *request_len,
                                uint8_t *response_buf, size_t *response_len);

/**
 * @brief 将一组HTTP请求响应对输出到文件
 * @param request HTTP请求内容
 * @param request_len 请求长度
 * @param response HTTP响应内容
 * @param response_len 响应长度
 */
static void output_http_to_file(const uint8_t *request, size_t request_len,
                                 const uint8_t *response, size_t response_len);

/**
 * @brief 释放单条TCP流的所有内存
 */
static void free_stream(tcp_stream_t *stream);

// ===================== 对外接口实现 =====================
void reassembly_init(void)
{
    // 1. 初始化流表为空
    stream_table = NULL;
    http_pair_count = 0;

    // 2. 创建HTTP结果输出目录（后续补充mkdir实现）
    printf("[Reassembly] TCP流重组模块初始化完成\n");
}

void reassembly_record(const struct parsed_packet *pkt)
{
    // 前置校验：非TCP包直接忽略
    if (pkt->proto != PROTO_TCP && pkt->proto != PROTO_HTTP) {
        return;
    }
    if (pkt->payload_len == 0 || pkt->payload == NULL) {
        return;
    }

    // 1. 查找对应TCP流，不存在则新建
    tcp_stream_t *stream = find_stream(pkt);
    if (stream == NULL) {
        stream = create_stream(pkt);
    }

    // 2. 判断报文方向，插入对应方向的片段链表
    // 此处简化判断：源端口+源IP匹配流的客户端则为c2s方向（后续完善精准匹配）
    int is_client_to_server = 1; // 临时占位，后续补充方向判断逻辑
    if (is_client_to_server) {
        insert_segment(&stream->client_to_server, pkt->tcp_seq, pkt->payload, pkt->payload_len);
        // 3. 尝试拼接连续片段
        merge_contiguous_segments(&stream->client_to_server, &stream->c2s_buf, &stream->c2s_buf_len);
    } else {
        insert_segment(&stream->server_to_client, pkt->tcp_seq, pkt->payload, pkt->payload_len);
        merge_contiguous_segments(&stream->server_to_client, &stream->s2c_buf, &stream->s2c_buf_len);
    }

    // 4. 尝试从已拼接的缓冲区中提取HTTP请求响应对
    extract_http_pairs(stream->c2s_buf, &stream->c2s_buf_len,
                       stream->s2c_buf, &stream->s2c_buf_len);
}

void reassembly_finish(void)
{
    printf("[Reassembly] 开始收尾处理，共输出 %d 组HTTP请求响应对\n", http_pair_count);

    // 1. 遍历所有流，处理剩余未输出的HTTP数据
    tcp_stream_t *curr = stream_table;
    while (curr != NULL) {
        tcp_stream_t *next = curr->next;
        // 处理流内剩余缓冲区
        free_stream(curr);
        curr = next;
    }

    // 2. 重置流表
    stream_table = NULL;
    printf("[Reassembly] 资源清理完成，模块退出\n");
}

// ===================== 内部函数空实现（后续逐步填充） =====================
static tcp_stream_t* find_stream(const struct parsed_packet *pkt)
{
    // 后续实现：遍历流表，按五元组匹配
    return NULL;
}

static tcp_stream_t* create_stream(const struct parsed_packet *pkt)
{
    // 后续实现：分配内存、填充五元组、插入流表头部
    return NULL;
}

static void insert_segment(tcp_segment_t **head, uint32_t seq, const uint8_t *payload, size_t len)
{
    // 后续实现：按seq升序插入链表，去重重叠片段
}

static void merge_contiguous_segments(tcp_segment_t **head, uint8_t **buf, size_t *buf_len)
{
    // 后续实现：遍历链表，拼接连续seq的片段到缓冲区
}

static void extract_http_pairs(uint8_t *request_buf, size_t *request_len,
                                uint8_t *response_buf, size_t *response_len)
{
    // 后续实现：匹配HTTP请求行/响应行，识别Content-Length，切割完整请求响应对
}

static void output_http_to_file(const uint8_t *request, size_t request_len,
                                 const uint8_t *response, size_t response_len)
{
    // 后续实现：按序号命名，输出到http_output目录
    http_pair_count++;
}

static void free_stream(tcp_stream_t *stream)
{
    // 后续实现：释放片段链表、缓冲区、流节点本身
}