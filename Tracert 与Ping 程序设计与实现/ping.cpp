#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <thread>
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")
using namespace std;

const int ICMP_ECHO_REQUEST = 8;    // ICMP 回显请求类型
const int ICMP_ECHO_REPLY = 0;      // ICMP 回显应答类型
const int DEF_ICMP_DATA_SIZE = 32;  // ICMP 数据部分大小
const int MAX_ICMP_PACKET_SIZE = 1024; // 最大 ICMP 报文大小
const int PING_TIMEOUT = 1000;      // 超时时间（毫秒）

mutex cout_mutex;  // 输出互斥锁，避免多线程打印冲突

struct ICMP_HEADER {
    BYTE type;      // 类型
    BYTE code;      // 代码
    USHORT checksum; // 校验和
    USHORT id;      // 标识符
    USHORT seq;     // 序列号
};

// 计算校验和
USHORT checksum(USHORT* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

// Ping 功能：测试某个 IP 是否在线
bool PingHost(const string& ip) {
    SOCKET sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in dest;
    ZeroMemory(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    char sendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];
    memset(sendBuf, 0, sizeof(sendBuf));

    ICMP_HEADER* icmpHeader = (ICMP_HEADER*)sendBuf;
    icmpHeader->type = ICMP_ECHO_REQUEST;
    icmpHeader->code = 0;
    icmpHeader->checksum = 0;
    icmpHeader->id = (USHORT)GetCurrentProcessId();
    icmpHeader->seq = 0;

    memset(sendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);
    icmpHeader->checksum = checksum((USHORT*)sendBuf, sizeof(sendBuf));

    int timeout = PING_TIMEOUT;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    if (sendto(sock, sendBuf, sizeof(sendBuf), 0, (sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    char recvBuf[MAX_ICMP_PACKET_SIZE];
    sockaddr_in from;
    int fromLen = sizeof(from);

    if (recvfrom(sock, recvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &fromLen) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    closesocket(sock);
    return true;
}

// 域名解析为 IP
bool ResolveDomain(const string& domain, string& ip) {
    addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain.c_str(), NULL, &hints, &result) != 0) {
        return false;
    }

    sockaddr_in* addr = (sockaddr_in*)result->ai_addr;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ipStr, INET_ADDRSTRLEN);

    ip = string(ipStr);
    freeaddrinfo(result);
    return true;
}

// 将字符串形式的 IP 转为整数
unsigned long IpToLong(const string& ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

// 将整数形式的 IP 转为字符串
string LongToIp(unsigned long ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
    return string(ipStr);
}

// Ping 扫描指定范围
void ScanRange(const string& startIp, const string& endIp, vector<string>& onlineHosts) {
    unsigned long start = IpToLong(startIp);
    unsigned long end = IpToLong(endIp);

    for (unsigned long ip = start; ip <= end; ++ip) {
        string ipStr = LongToIp(ip);
        if (PingHost(ipStr)) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "Host " << ipStr << " is online." << endl;
            onlineHosts.push_back(ipStr);
        }
    }
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    string startInput, endInput;
    cout << "Enter the start IP or domain: ";
    cin >> startInput;
    cout << "Enter the end IP or domain: ";
    cin >> endInput;

    string startIp = startInput, endIp = endInput;
    if (!ResolveDomain(startInput, startIp)) {
        cout << "Failed to resolve start IP or domain: " << startInput << endl;
        WSACleanup();
        return 1;
    }
    if (!ResolveDomain(endInput, endIp)) {
        cout << "Failed to resolve end IP or domain: " << endInput << endl;
        WSACleanup();
        return 1;
    }

    vector<string> onlineHosts;
    ScanRange(startIp, endIp, onlineHosts);

    cout << "\nScan complete. Online hosts between " << startInput << " and " << endInput << ":\n";
    for (const auto& ip : onlineHosts) {
        cout << ip << endl;
    }

    WSACleanup();
    system("pause");
    return 0;
}
