/*
 * yg_net.h
 *
 *  Created on: 2016年6月16日
 *      Author: yegui
 */

#ifndef DEV_HP_UTIL_BASE_YG_NET_H_
#define DEV_HP_UTIL_BASE_YG_NET_H_

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "yg_assert.h"

enum {
	T_NET_TCP = 1,
	T_NET_UDP = 2
};

#define NET_START_SIGN 	  0x11111111
enum {
	T_NET_HEAD_TYPE_JSON  = 0x02
};

#pragma pack(1)
struct NetHead
{
    uint32_t       ucStart;   	/* 魔数 */
    uint8_t		   ucType;		/* 方法,兼容包体多协议 */
    uint32_t       uPkgLen;		/* 包长 */
};
#pragma pack()

int yg_get_ipbyhost(const char *phost, char *ipVec[64], unsigned int size);

/*
 * type: T_NET_TCP| T_NET_UDP
 *
 */
int yg_get_connect(const char *pIp, unsigned int port, char type, char isNoBlock);
int yg_get_connect_unix(const char *path, char type, char isNoBlock);
int yg_socket_unix_bind(const char *path, int num, char isNoBlock);
int yg_socket_tcpip_bind(const char *pip, unsigned int port, int num, char isNoBlock);

/*
 *  会在基础上追加网络头,将采用阻塞模式
 */
int yg_packet_head_pack(struct NetHead *pNetHead, char *pbuf, unsigned int bufSize);
int yg_packet_head_unpack(struct NetHead *pNetHead, const char *pbuf, unsigned int bufLen);


int yg_packet_tcp_send_block(int sock, const char *pcnt, unsigned int cntLen, char bodyNetType);
int yg_packet_tcp_recv_block(int sock, char *pcnt, unsigned int size, char *bodyNetType);


#endif /* DEV_HP_UTIL_BASE_YG_NET_H_ */
