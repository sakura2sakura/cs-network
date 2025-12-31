#include <iostream>               // 标准输入输出头文件
#include <winsock2.h>             // Windows 套接字头文件
#include <ws2tcpip.h>             // 提供 IP 地址和主机名解析功能
using namespace std;

#pragma comment(lib, "Ws2_32.lib") // 链接 Windows 套接字库

// IP 报头结构定义
typedef struct
{
	unsigned char hdr_len : 4;    // 4 位报头长度（以 4 字节为单位）
	unsigned char version : 4;   // 4 位 IP 协议版本号
	unsigned char tos;           // 服务类型
	unsigned short total_len;    // 数据包总长度
	unsigned short identifier;   // 标识符
	unsigned short frag_and_flags; // 分段及标志位
	unsigned char ttl;           // 生存时间（跳数限制）
	unsigned char protocol;      // 上层协议类型
	unsigned short checksum;     // 报头校验和
	unsigned long sourceIP;      // 源 IP 地址
	unsigned long destIP;        // 目标 IP 地址
} IP_HEADER;

// ICMP 报头结构定义
typedef struct
{
	BYTE type;         // 类型字段（如 8 为请求回显，0 为回显应答）
	BYTE code;         // 代码字段
	USHORT cksum;      // 校验和
	USHORT id;         // 标识符
	USHORT seq;        // 序列号
} ICMP_HEADER;

// 解码结果结构定义
typedef struct
{
	USHORT usSeqNo;        // 序列号
	DWORD dwRoundTripTime; // 往返时间（毫秒）
	in_addr dwIPaddr;      // 返回报文的 IP 地址
} DECODE_RESULT;

// 校验和计算函数
USHORT checksum(USHORT *pBuf, int iSize)
{
	unsigned long cksum = 0;      // 累计校验和变量
	while (iSize > 1)             // 遍历缓冲区，逐对字节相加
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT);
	}
	if (iSize)                    // 如果还有一个字节
	{
		cksum += *(UCHAR *)pBuf;  // 加上最后的单字节
	}
	cksum = (cksum >> 16) + (cksum & 0xffff); // 高 16 位与低 16 位相加
	cksum += (cksum >> 16);       // 再次处理溢出
	return (USHORT)(~cksum);      // 取反返回校验和
}

// 解码 ICMP 响应报文函数
BOOL DecodeIcmpResponse(char *pBuf, int iPacketSize, DECODE_RESULT &DecodeResult, BYTE ICMP_ECHO_REPLY, BYTE ICMP_TIMEOUT)
{
	IP_HEADER *pIpHdr = (IP_HEADER *)pBuf; // 提取 IP 报头
	int iIpHdrLen = pIpHdr->hdr_len * 4;   // 计算 IP 报头长度
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER))) // 检查报文大小合法性
		return FALSE;
	
	ICMP_HEADER *pIcmpHdr = (ICMP_HEADER *)(pBuf + iIpHdrLen); // 提取 ICMP 报头
	USHORT usID, usSquNo;                                      // 定义 ID 和序列号变量
	if (pIcmpHdr->type == ICMP_ECHO_REPLY)                     // 如果是回显应答报文
	{
		usID = pIcmpHdr->id;                                   // 获取 ID
		usSquNo = pIcmpHdr->seq;                               // 获取序列号
	}
	else if (pIcmpHdr->type == ICMP_TIMEOUT)                   // 如果是超时报文
	{
		char *pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER); // 提取载荷中的 IP 报头
		int iInnerIPHdrLen = ((IP_HEADER *)pInnerIpHdr)->hdr_len * 4; // 计算载荷中 IP 报头长度
		ICMP_HEADER *pInnerIcmpHdr = (ICMP_HEADER *)(pInnerIpHdr + iInnerIPHdrLen); // 提取载荷中 ICMP 报头
		usID = pInnerIcmpHdr->id;                               // 获取 ID
		usSquNo = pInnerIcmpHdr->seq;                           // 获取序列号
	}
	else
	{
		return FALSE;                                           // 非期望类型，返回错误
	}
	
	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != DecodeResult.usSeqNo) // 验证 ID 和序列号
		return FALSE;
	
	DecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;            // 记录返回报文的源 IP 地址
	DecodeResult.dwRoundTripTime = GetTickCount() - DecodeResult.dwRoundTripTime; // 计算往返时间
	
	if (pIcmpHdr->type == ICMP_ECHO_REPLY || pIcmpHdr->type == ICMP_TIMEOUT) // 输出往返时间信息
	{
		if (DecodeResult.dwRoundTripTime)
			cout << "      " << DecodeResult.dwRoundTripTime << "ms" << flush;
		else
			cout << "      " << "<1ms" << flush;
	}
	return TRUE;
}

// 主函数
int main()
{
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);                // 初始化套接字环境
	char IpAddress[255];
	cout << "请输入一个IP地址或域名：";
	cin >> IpAddress;
	
	u_long ulDestIP = inet_addr(IpAddress);          // 转换为 IP 地址
	if (ulDestIP == INADDR_NONE)                    // 如果无效，尝试按域名解析
	{
		hostent *pHostent = gethostbyname(IpAddress);
		if (pHostent)
		{
			ulDestIP = (*(in_addr *)pHostent->h_addr).s_addr; // 获取解析到的 IP 地址
		}
		else
		{
			cout << "输入的IP地址或域名无效!" << endl;
			WSACleanup();
			return 0;
		}
	}
	
	cout << "Tracing route to " << IpAddress << " with a maximum of 30 hops.\n" << endl;
	
	sockaddr_in destSockAddr;                       // 定义目标套接字地址
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in)); // 清零地址结构
	destSockAddr.sin_family = AF_INET;
	destSockAddr.sin_addr.s_addr = ulDestIP;
	
	SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED); // 创建原始套接字
	int iTimeout = 3000;                            // 设置超时时间
	setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&iTimeout, sizeof(iTimeout)); // 接收超时
	setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&iTimeout, sizeof(iTimeout)); // 发送超时
	
	const BYTE ICMP_ECHO_REQUEST = 8;               // ICMP 请求回显
	const BYTE ICMP_ECHO_REPLY = 0;                 // ICMP 回显应答
	const BYTE ICMP_TIMEOUT = 11;                   // ICMP 传输超时
	
	const int DEF_ICMP_DATA_SIZE = 32;              // 默认 ICMP 数据字段大小
	const int MAX_ICMP_PACKET_SIZE = 1024;          // 最大 ICMP 报文长度
	const DWORD DEF_ICMP_TIMEOUT = 3000;            // 默认超时时间
	const int DEF_MAX_HOP = 30;                     // 默认最大跳数
	
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE]; // 定义发送缓冲区
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));                // 初始化缓冲区
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];                     // 定义接收缓冲区
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));                // 初始化缓冲区
	
	ICMP_HEADER *pIcmpHeader = (ICMP_HEADER *)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST;                      // 设置 ICMP 类型
	pIcmpHeader->code = 0;                                      // 设置代码字段
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();            // 设置标识符
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE); // 填充数据字段
	
	USHORT usSeqNo = 0;                                         // ICMP 报文序列号
	int iTTL = 1;                                               // 初始 TTL
	BOOL bReachDestHost = FALSE;                                // 标记是否到达目的地
	int iMaxHot = DEF_MAX_HOP;                                  // 最大跳站数
	DECODE_RESULT DecodeResult;                                 // 解码结果
	
	while (!bReachDestHost && iMaxHot--)                        // 循环发送和接收报文
	{
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char *)&iTTL, sizeof(iTTL)); // 设置 TTL
		cout << iTTL << flush;                                  // 输出当前跳数
		((ICMP_HEADER *)IcmpSendBuf)->cksum = 0;               // 清空校验和
		((ICMP_HEADER *)IcmpSendBuf)->seq = htons(usSeqNo++);   // 设置序列号
		((ICMP_HEADER *)IcmpSendBuf)->cksum = checksum((USHORT *)IcmpSendBuf,
			sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE); // 计算校验和
		
		DecodeResult.usSeqNo = ((ICMP_HEADER *)IcmpSendBuf)->seq; // 记录序列号
		DecodeResult.dwRoundTripTime = GetTickCount();            // 记录时间
		sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr *)&destSockAddr, sizeof(destSockAddr)); // 发送数据
		
		sockaddr_in from;        // 定义接收端地址
		int iFromLen = sizeof(from);
		int iReadDataLen;        // 接收数据长度
		
		while (1)
		{
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr *)&from, &iFromLen); // 接收数据
			if (iReadDataLen != SOCKET_ERROR)                            // 检查接收结果
			{
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, DecodeResult, ICMP_ECHO_REPLY, ICMP_TIMEOUT)) // 解析数据
				{
					if (DecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr) // 检查是否到达目标
						bReachDestHost = TRUE;
					cout << '\t' << inet_ntoa(DecodeResult.dwIPaddr) << endl; // 输出 IP 地址
					break;
				}
			}
			else if (WSAGetLastError() == WSAETIMEDOUT)                  // 超时处理
			{
				cout << "         *" << '\t' << "Request timed out." << endl;
				break;
			}
			else
			{
				break;
			}
		}
		iTTL++;    // 递增 TTL
	}
	system("pause");
}

