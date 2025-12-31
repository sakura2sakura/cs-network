#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUF 256
#define RECVBUF 65536  // 适当调大，以防止数据截断

// ========================
// =  以太网、IP、TCP、UDP 结构
// ========================

// 注意：在Windows原生Raw Socket下，通常拿不到Ethernet Header
// 下列结构仅示例完整的协议头定义；若使用WinPcap / Npcap，可直接解析Ethernet帧头

// 以太网头部结构（通常 Windows RAW Socket 拿不到）
typedef struct ethernet_header {
    unsigned char dest[6];    // 目标 MAC 地址
    unsigned char src[6];     // 源 MAC 地址
    unsigned short type;      // 上层协议类型
} ETHERNET_HEADER;

// IP 头部结构
typedef struct ip_header {
    unsigned char  version_ihl;    // 版本 (4 bits) + 头部长度 (4 bits)
    unsigned char  tos;            // 服务类型
    unsigned short length;         // 总长度
    unsigned short id;             // 标识符
    unsigned short flags_offset;   // 标志 + 片偏移
    unsigned char  ttl;            // 生存时间
    unsigned char  protocol;       // 协议类型
    unsigned short checksum;       // 校验和
    unsigned int   src_addr;       // 源 IP 地址
    unsigned int   dest_addr;      // 目标 IP 地址
} IP_HEADER;

// TCP 头部结构
typedef struct tcp_header {
    unsigned short src_port;   // 源端口
    unsigned short dest_port;  // 目标端口
    unsigned int seq;          // 序列号
    unsigned int ack;          // 确认号
    unsigned char offset_res;  // 数据偏移 + 保留
    unsigned char flags;       // 标志位
    unsigned short window;     // 窗口大小
    unsigned short checksum;   // 校验和
    unsigned short urgent;     // 紧急指针
} TCP_HEADER;

// UDP 头部结构
typedef struct udp_header {
    unsigned short src_port;   // 源端口
    unsigned short dest_port;  // 目标端口
    unsigned short length;     // 长度
    unsigned short checksum;   // 校验和
} UDP_HEADER;

// ========================
// = 解析函数示例
// ========================

// 解析以太网头部（仅示例；Windows下Raw Socket通常获取不到）
void parse_ethernet(const unsigned char* buffer) {
    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)buffer;
    printf("Ethernet Header:\n");
    printf("\tDestination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
    printf("\tSource MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    printf("\tType: 0x%04X\n", ntohs(eth->type));
}

// 解析 IP 头部（注意该结构体与上面定义对应）
// 如果使用原生 Raw Socket (IP 层抓包)，则收到的数据包开头往往就是 IP Header，而没有以太网帧头
void parse_ip(const unsigned char* buffer, int size) {
    if (size < sizeof(IP_HEADER)) {
        printf("Packet too small for IP header.\n");
        return;
    }

    IP_HEADER* ip = (IP_HEADER*)buffer;
    unsigned char ihl = ip->version_ihl & 0x0F; // IP头长度的4个低位bit
    unsigned char version = ip->version_ihl >> 4;
    printf("IP Header:\n");
    printf("\tVersion: %d\n", version);
    printf("\tIHL (IP Header Length): %d (words) => %d (bytes)\n", ihl, ihl * 4);
    printf("\tTotal Length: %d\n", ntohs(ip->length));
    printf("\tIdentification: %d\n", ntohs(ip->id));
    printf("\tTTL: %d\n", ip->ttl);
    printf("\tProtocol: %d\n", ip->protocol);
    printf("\tSource IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->src_addr));
    printf("\tDestination IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->dest_addr));
}

// 解析 TCP 头部
void parse_tcp(const unsigned char* buffer, int ipHeaderLen, int size) {
    if (size < ipHeaderLen + sizeof(TCP_HEADER)) {
        printf("Packet too small for TCP header.\n");
        return;
    }
    TCP_HEADER* tcp = (TCP_HEADER*)(buffer + ipHeaderLen);
    printf("TCP Header:\n");
    printf("\tSource Port: %d\n", ntohs(tcp->src_port));
    printf("\tDestination Port: %d\n", ntohs(tcp->dest_port));
}

// 解析 UDP 头部
void parse_udp(const unsigned char* buffer, int ipHeaderLen, int size) {
    if (size < ipHeaderLen + sizeof(UDP_HEADER)) {
        printf("Packet too small for UDP header.\n");
        return;
    }
    UDP_HEADER* udp = (UDP_HEADER*)(buffer + ipHeaderLen);
    printf("UDP Header:\n");
    printf("\tSource Port: %d\n", ntohs(udp->src_port));
    printf("\tDestination Port: %d\n", ntohs(udp->dest_port));
}

// ========================
// = 主函数: 结合第一段的IP层抓包 + 简易解析示例
// ========================
int main() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        printf("Error at WSAStartup: %d\n", WSAGetLastError());
        return 1;
    }

    // 创建原始套接字 (IP 层)
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed. Error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    char hostname[BUF] = { 0 };
    if (gethostname(hostname, BUF) == SOCKET_ERROR) {
        printf("Get hostname failed. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    struct hostent* phost = gethostbyname(hostname);
    if (phost == NULL) {
        printf("Get host by name failed. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Available network interfaces:\n");
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);

    int i = 0;
    while (phost->h_addr_list[i]) {
        memcpy(&(addr.sin_addr), phost->h_addr_list[i], phost->h_length);
        printf("[%d] %s\n", i, inet_ntoa(addr.sin_addr));
        i++;
    }

    int index = -1;
    do {
        printf("Select an interface for sniffing (0-%d): ", i - 1);
        scanf("%d", &index);
    } while (index < 0 || index >= i);

    memcpy(&(addr.sin_addr), phost->h_addr_list[index], phost->h_length);

    // 绑定到选定的网卡IP
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("Bind failed. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 开启混杂模式
    unsigned long flag = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &flag) != 0) {
        printf("Failed to enable promiscuous mode. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    unsigned char recvbuf[RECVBUF];
    int count = 0;

    printf("Listening for packets (IP layer)...\n");
    while (count < 20) { // 限制最多处理 20 个数据包
        int size = recv(sock, (char*)recvbuf, RECVBUF, 0);
        if (size <= 0) {
            printf("Receive failed. Error: %d\n", WSAGetLastError());
            break;
        }

        count++;
        printf("Packet [%d] - Size: %d bytes\n", count, size);

        // =============================
        // 此处演示：因为 Windows RAW Socket 拿到的往往是从 IP 头开始的数据
        // parse_ethernet(...) 理论上是解析不到正确内容的
        // =============================

        // 1) 解析 IP 头
        parse_ip(recvbuf, size);

        // 2) 确定协议类型，并解析 TCP/UDP 头
        //    注意：IP Header 长度是 IHL*4，如果需要精确分层，需要先算出 IP 头长度
        IP_HEADER* ip = (IP_HEADER*)recvbuf;
        unsigned char ihl = ip->version_ihl & 0x0F;
        int ipHeaderLen = ihl * 4;

        switch (ip->protocol) {
        case IPPROTO_TCP:
            parse_tcp(recvbuf, ipHeaderLen, size);
            break;
        case IPPROTO_UDP:
            parse_udp(recvbuf, ipHeaderLen, size);
            break;
        case IPPROTO_ICMP:
            printf("ICMP Packet (no detailed parse here).\n");
            break;
        default:
            printf("Unknown or Unsupported Protocol: %d\n", ip->protocol);
            break;
        }

        printf("\n");
    }

    printf("Reached maximum packet limit (20). Exiting...\n");
    closesocket(sock);
    WSACleanup();
    system("pause");
    return 0;
}
