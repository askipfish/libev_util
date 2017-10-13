/*
 * yg_net.c
 *
 *  Created on: 2016年6月16日
 *      Author: yegui
 */

#include "yg_net.h"

int yg_get_ipbyhost(const char *phost, char *ipVec[64], unsigned int size)
{
    struct hostent *hostInfo = gethostbyname(phost);
    if(hostInfo == NULL) {
        printf("host: %s not ip\n", phost);
        return -1;
    }
    
    if(hostInfo->h_addr_list == NULL) return 0;

    int icount = 0;
    unsigned int i;
    for(i = 0; i < hostInfo->h_length; i++) {
        if(hostInfo->h_addr_list[i] == NULL) break;

        if(hostInfo->h_addrtype != AF_INET && hostInfo->h_addrtype != AF_INET6)
        	continue;

        inet_ntop(hostInfo->h_addrtype, hostInfo->h_addr_list[i], ipVec[icount], 64);
        icount += 1;
        if(icount >= size) break;
    }

    return icount;
}

int yg_packet_head_pack(struct NetHead *pNetHead, char *pbuf, unsigned int bufSize)
{
	YG_ASSERT_RET(pNetHead != NULL, -1);
	YG_ASSERT_RET(pbuf != NULL, -1);

	char *p = pbuf;

	uint32_t *pInt = (uint32_t *)p;
	*pInt = htonl(pNetHead->ucStart);
	p += 4;

	*p = pNetHead->ucType;
	p += 1;

	pInt = (uint32_t *)p;
	*pInt = htonl(pNetHead->uPkgLen);
	p += 4;

	return p - pbuf;
}

int yg_packet_head_unpack(struct NetHead *pNetHead, const char *pbuf, unsigned int bufLen)
{
	YG_ASSERT_RET(pNetHead != NULL, -1);
	YG_ASSERT_RET(pbuf != NULL, -1);
	YG_ASSERT_RET(bufLen >= sizeof(struct NetHead), -1);

	const char *p = pbuf;
	const uint32_t *pInt = (const uint32_t *)p;
	pNetHead->ucStart = ntohl(*pInt); p += 4;

	pNetHead->ucType = *p; p += 1;

	pInt = (const uint32_t *)p;
	pNetHead->uPkgLen = ntohl(*pInt); p += 4;

	if(pNetHead->ucStart != NET_START_SIGN) {
		YG_ERR("ucStart: %d != start_sign: %d", pNetHead->ucStart, NET_START_SIGN);
		return -1;
	}

	return p - pbuf;
}

int yg_tcp_send_block(int sock, const char *pcnt, unsigned int cntLen)
{
  int sendTotal = 0;
  while(sendTotal < cntLen) {
      int sendLen = send(sock, pcnt + sendTotal, cntLen - sendTotal, 0);
      if(sendLen <= 0) {
          YG_ERR("send(%d) ERR(%d) %s!", sock, sendLen, strerror(errno));
          return -1;
      }

      sendTotal += sendLen;
  }

  return sendTotal;
}

int yg_tcp_recv_block(int sock, char *pcnt, unsigned int cntLen)
{
    int recvTotal = 0;
    while(recvTotal < cntLen) {
        int recvLen = recv(sock, pcnt + recvTotal, cntLen - recvTotal, 0);
        if(recvLen <= 0) {
            YG_ERR("recv(%d) err: %d, error: %s", sock, recvLen, strerror(errno));
            return -1;
        }

        recvTotal += recvLen;
    }

    return recvTotal;
}

int yg_packet_tcp_send_block(int sock, const char *pcnt, unsigned int cntLen, char bodyNetType)
{
	YG_ASSERT_RET(pcnt != NULL, -1);

	struct NetHead netHead;
	netHead.ucStart = NET_START_SIGN;
	netHead.ucType = bodyNetType;
	netHead.uPkgLen = sizeof(netHead) + cntLen;

	char sendBuf[sizeof(netHead)];
	int headLen = yg_packet_head_pack(&netHead, sendBuf, sizeof(netHead));
	YG_ASSERT_RET(headLen > 0, -1);

	int iRet = yg_tcp_send_block(sock, sendBuf, headLen);
	YG_ASSERT_RET(iRet >= 0, -1);

	iRet = yg_tcp_send_block(sock, pcnt, cntLen);
	YG_ASSERT_RET(iRet >= 0, -1);

	return 0;
}

int yg_packet_tcp_recv_block(int sock, char *pcnt, unsigned int size, char *bodyNetType)
{
	YG_ASSERT_RET(pcnt != NULL, -1);
	YG_ASSERT_RET(size >= sizeof(struct NetHead), -1);

	int cntIdx = 0;
	cntIdx = yg_tcp_recv_block(sock, pcnt, sizeof(struct NetHead));
	YG_ASSERT_RET(cntIdx >= 0, -1);
 
	struct NetHead netHead;
	int headLen = yg_packet_head_unpack(&netHead, pcnt, cntIdx);
	YG_ASSERT_RET(headLen > 0, -1);

	if(netHead.uPkgLen > size) {
		YG_ERR("pkgLen: %d > size: %d", netHead.uPkgLen, size);
		return -1;
	}


	/* skip netHead */
	if(cntIdx > sizeof(netHead))
		memcpy(pcnt, pcnt + sizeof(struct NetHead), cntIdx - sizeof(struct NetHead));

    // then ,we recv other data
	int recvLen = yg_tcp_recv_block(sock, pcnt + cntIdx - sizeof(struct NetHead), netHead.uPkgLen - cntIdx);
	YG_ASSERT_RET(recvLen >= 0, -1);


	return netHead.uPkgLen - sizeof(struct NetHead);
}


int yg_socket_tcpip_bind(const char *pip, unsigned int port, int num, char isNoBlock)
{
    YG_ASSERT_RET(pip != NULL, -1);

    int sock;

    if(num > 0)  sock = socket(AF_INET, SOCK_STREAM, 0);
    else sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) {
        YG_ERR("socket err(%s)", strerror(errno));
        return -1;
    }
   
    int iflags;
    int iRet;
    if(isNoBlock == 1) {
        iflags = fcntl(sock, F_GETFL);
        iRet = fcntl(sock, F_SETFL, iflags | O_NONBLOCK);
        if(iRet < 0) {
            YG_ERR("fcntl(%d) ERR(%s)", sock, strerror(errno));
            close(sock);
            return -1;
        }
    }

    iRet = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &iflags, sizeof(iflags));
    if(iRet < 0) {
        YG_ERR("setsockopt(%d) ERR(%s)", sock, strerror(errno));
        close(sock);
        return -1;
    }

    struct sockaddr_in addr;
    bzero(&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(pip);
    addr.sin_port = htons(port);
    iRet = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(iRet < 0) {
        YG_ERR("bind(%d) ERR(%s)", sock, strerror(errno));
        close(sock);
        return -1;
    }

    if(num > 0) {
        iRet = listen(sock, num);
        if(iRet < 0) {
            YG_ERR("listen(%d) ERR(%s)", sock, strerror(errno));
            close(sock);
            return -1;
        }
    }

    return sock;
}

int yg_socket_unix_bind(const char *path, int num, char isNoBlock)
{
    YG_ASSERT_RET(path != NULL, -1);

    int iRet;
    int sock;

    if(num > 0)  sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    else sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
    if(sock == -1) {
        YG_ERR("socket err(%s)", strerror(errno));
        return -1;
    }

    int iflags;
    if(isNoBlock) {
		iflags = fcntl(sock, F_GETFL);
		iRet = fcntl(sock, F_SETFL, iflags | O_NONBLOCK);
		if(iRet < 0) {
			YG_ERR("fcntl(%d) ERR(%s)", sock, strerror(errno));
			close(sock);
			return -1;
		}
    }

    unlink(path);
    iRet = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &iflags, sizeof(iflags));
    if(iRet < 0) {
        YG_ERR("setsockopt(%d) ERR(%s)", sock, strerror(errno));
        close(sock);
        return -1;
    }

    struct sockaddr_un addr;
    bzero(&addr, sizeof(struct sockaddr_un));

    addr.sun_family = AF_LOCAL;
    strcpy((void*)&addr.sun_path, path);
    iRet = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(iRet < 0) {
        YG_ERR("bind(%d) ERR(%s)", sock, strerror(errno));
        close(sock);
        return -1;
    }

    if(num > 0) {
        iRet = listen(sock, num);
        if(iRet < 0) {
            YG_ERR("listen(%d) ERR(%s)", sock, strerror(errno));
            close(sock);
            return -1;
        }
    }

    return sock;
}

int yg_get_connect(const char *pip, unsigned int port, char type, char isNoBlock)
{
	YG_ASSERT_RET(pip != NULL, -1);

	int sock;

	if(type == T_NET_TCP)
		sock = socket(AF_INET, SOCK_STREAM, 0);
	else
		sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		YG_ERR("socket err(%s)", strerror(errno));
		return -1;
	}


	struct sockaddr_in addr;
	bzero(&addr, sizeof(struct sockaddr_in));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(pip);
	addr.sin_port = htons(port);

	int iRet = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
    if(iRet == -1 && errno == EINPROGRESS)
        return sock;

	if (iRet < 0) {
		YG_ERR("connect(%d) ERR(%d)", sock, errno);
		close(sock);
		return -1;
	}

	if(isNoBlock) {
	    int iflags = fcntl(sock, F_GETFL);
	    int iRet = fcntl(sock, F_SETFL, iflags | O_NONBLOCK);
	    if(iRet < 0) {
	        YG_ERR("fcntl(%d) ERR(%s)", sock, strerror(errno));
	        close(sock);
	        return -1;
	    }
	}

	return sock;
}

int yg_get_connect_unix(const char *path, char type, char isNoBlock)
{
	YG_ASSERT_RET(path != NULL, -1);

	int sock;

	if(type == T_NET_TCP)
		sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	else
		sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
		YG_ERR("socket err(%s)", strerror(errno));
		return -1;
	}

	if(isNoBlock) {
	    int iflags = fcntl(sock, F_GETFL);
	    int iRet = fcntl(sock, F_SETFL, iflags | O_NONBLOCK);
	    if(iRet < 0) {
	        YG_ERR("fcntl(%d) ERR(%s)", sock, strerror(errno));
	        close(sock);
	        return -1;
	    }
	}

	struct sockaddr_un addr;
	bzero(&addr, sizeof(struct sockaddr_un));

	addr.sun_family = AF_LOCAL;
	strcpy((void*)&addr.sun_path, path);

	int iRet = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (iRet < 0) {
		YG_ERR("bind(%d) ERR(%s)", sock, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}
