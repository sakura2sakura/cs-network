#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUF 256
#define RECVBUF 1500

// 数据包头部定义
typedef struct ip_header {
    unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    unsigned char  tos;            // Type of service
    unsigned short tlen;           // Total length
    unsigned short identification; // Identification
    unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    unsigned char  ttl;            // Time to live
    unsigned char  proto;          // Protocol
    unsigned short crc;            // Header checksum
    unsigned int   saddr;          // Source address
    unsigned int   daddr;          // Destination address
} IP_HEADER, *PIP_HEADER;

int main() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        printf("Error at WSAStartup: %d\n", WSAGetLastError());
        return 1;
    }

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

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("Bind failed. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    unsigned long flag = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &flag) != 0) {
        printf("Failed to enable promiscuous mode. Error: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    char recvbuf[RECVBUF];
    int count = 0;

    printf("Listening for packets...\n");
    while (count < 20) { // 限制最多处理 20 条数据包
        int size = recv(sock, recvbuf, RECVBUF, 0);
        if (size <= 0) {
            printf("Receive failed. Error: %d\n", WSAGetLastError());
            break;
        }

        count++;
        printf("Packet [%d] - Size: %d bytes\n", count, size);

        PIP_HEADER ipHeader = (PIP_HEADER)recvbuf;
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ipHeader->daddr));
        printf("Protocol: %d\n", ipHeader->proto);

        switch (ipHeader->proto) {
        case IPPROTO_TCP:
            printf("TCP Packet\n");
            break;
        case IPPROTO_UDP:
            printf("UDP Packet\n");
            break;
        case IPPROTO_ICMP:
            printf("ICMP Packet\n");
            break;
        default:
            printf("Unknown Protocol\n");
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
