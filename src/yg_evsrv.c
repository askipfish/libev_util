/***********************************************************************
 * File : yg_evsrv.c
 * Brief: 
 * 
 * History
 * ---------------------------------------------------------------------
 * 2016-06-15     guichunpeng   1.0    created
 * 
 ***********************************************************************
 */

#include "yg_evsrv.h"

void ev_conf_free(struct EvConf *pConf);
void ev_ms_map_remove(struct EvMsMap *pevMap, int fd);

void ev_handler_accept(int sfd, short event, void *args);
void ev_handler_recv(int cfd, short event, void *args);
void ev_handler_send(int cfd, short event, void *args);

/*********************************************************************************
 *   ev_buf  interface implement
 *********************************************************************************/

int ev_buf_init(struct EvBuf *pbuf, unsigned int recvSize, unsigned int sendSize)
{
    memset(pbuf, 0, sizeof(struct EvBuf));

    YG_MALLOC(pbuf->pRecvBuf, recvSize, char *);
    if(pbuf->pRecvBuf == NULL) return -1;

    YG_MALLOC(pbuf->pSendBuf, sendSize, char *);
    if(pbuf->pSendBuf == NULL) {
        free(pbuf->pRecvBuf);
        return -1;
    }

    pbuf->recvSize = recvSize;
    pbuf->sendSize = sendSize;

    return 0;
}

void ev_buf_free(struct EvBuf *pbuf)
{
    if(pbuf->pRecvBuf != NULL) {
        free(pbuf->pRecvBuf);
        pbuf->pRecvBuf = NULL;
        pbuf->recvSize = 0;
    }

    if(pbuf->pSendBuf != NULL) {
        free(pbuf->pSendBuf);
        pbuf->pSendBuf = NULL;
        pbuf->sendSize = 0;
    }
}

int ev_buf_recv_check(struct EvBuf *pbuf)
{
	//YG_INFO("recvSize:%d, pbuf->pkgLen:%d, pRecvBuf:%x", pbuf->recvSize, pbuf->pkgLen, pbuf->pRecvBuf);
    int newRecvSize = pbuf->recvSize;
    if(pbuf->recvSize < pbuf->pkgLen + pbuf->ridx)
        newRecvSize =  pbuf->pkgLen + pbuf->ridx;
    else if(pbuf->pkgLen + pbuf->ridx <= BUFF_RECV_SIZE && pbuf->recvSize > BUFF_RECV_SIZE)
        newRecvSize = BUFF_RECV_SIZE;

    if(newRecvSize != pbuf->recvSize) {
		//YG_INFO("recvSize:%d, newRecvSize:%d, pRecvBuf:%x", pbuf->recvSize, newRecvSize, pbuf->pRecvBuf);
        pbuf->pRecvBuf = (char *)realloc(pbuf->pRecvBuf, newRecvSize);
        if(pbuf->pRecvBuf == NULL) {
            pbuf->recvSize = 0;
            YG_ERR("remalloc(%d) ERR(%s)", newRecvSize, strerror(errno));
            return -1;
        }
        pbuf->recvSize = newRecvSize;
    }

    return 0;
}

int ev_buf_send_check(struct EvBuf *pbuf, unsigned int cntLen)
{
    int newSendSize = pbuf->sendSize;
    if(pbuf->sendSize - pbuf->widx < cntLen)
        newSendSize =  pbuf->widx + cntLen;
    else if(cntLen + pbuf->widx <= BUFF_RECV_SIZE && pbuf->sendSize > BUFF_RECV_SIZE)
        newSendSize = BUFF_RECV_SIZE;

    if(newSendSize != pbuf->sendSize) {
        char *p = (char *)malloc(newSendSize);
        if(p == NULL) {
            YG_ERR("malloc(%d) ERR(%s)", newSendSize, strerror(errno));
            return -1;
        }
        memcpy(p, pbuf->pSendBuf, pbuf->widx);
        free(pbuf->pSendBuf);
        pbuf->pSendBuf = p;
        pbuf->sendSize = newSendSize;
    }

    return 0;
}

/*********************************************************************************
 *   ev session interace implement
 *********************************************************************************/

struct EvSession* ev_session_new(struct EvConf *pConf, unsigned int recvSize, unsigned int sendSize)
{
    int iRet;
    struct EvSession *pSession;

    YG_MALLOC(pSession, sizeof(struct EvSession), struct EvSession *);
    YG_ASSERT_RET(pSession != NULL, NULL);

    iRet = ev_buf_init(&pSession->evBuf, recvSize, sendSize);
    if(iRet == -1) {
        free(pSession);
        return NULL;
    }
    pSession->conf = pConf;

    return pSession;
}

void ev_session_free(struct EvSession *pSession)
{
    struct EvConf *pConf = pSession->conf;
    struct EvSrv *pSrv = pConf != NULL ? pConf->psrv : NULL;

    /* 补丁 服务端udp，是公用的不能随便释放 */
    if(pConf != NULL && pConf->isUdp == 1 && pConf->isCli == 0) return;

    /* 先回调后释放 */
    if(pConf != NULL && pSession->status != T_EV_LISTEN) {
        //YG_INFO("fd: %d, status: %d, %d, %d", pSession->fd, pSession->status, T_EV_LISTEN, T_EV_CONNED);
        if(pConf->pdeal_close_fun != NULL)
            pConf->pdeal_close_fun(pSession->fd);
    }

    /* 从map中删除 */
    if(pSrv != NULL && pSession->fd > 0) {
    	ev_ms_map_remove(&pSrv->evMsMap, pSession->fd);
    }

    /* 释放资源 */
    event_del(&pSession->rev);
    event_del(&pSession->wev);
    ev_buf_free(&pSession->evBuf);

    if(pSession->fd > 0) {
    	close(pSession->fd);
        pSession->fd = 0;

    }
    /* 补丁， 如果是客户端，则需要释放conf, 由业务驱动是否重连 */
    if(pConf != NULL && (pConf->isCli || pSession->status == T_EV_LISTEN))
    	ev_conf_free(pConf);

    ev_buf_free(&pSession->evBuf);
    free(pSession);
}

void ev_session_free_exit(struct EvSession *pSession)
{
    if(pSession->fd > 0)
    	close(pSession->fd);

    if(pSession->conf != NULL)
    	ev_conf_free(pSession->conf);

    ev_buf_free(&pSession->evBuf);
    free(pSession);
}

/*********************************************************************************
 *   ev_ms_map interface implement
 *********************************************************************************/
struct EvMsNode* ev_ms_node_new(int fd, struct EvSession *pSession)
{
	struct EvMsNode *pNode;
	YG_MALLOC(pNode, sizeof(struct EvMsNode), struct EvMsNode *);

	pNode->sock = fd;
	pNode->pSession = pSession;

	return pNode;
}


int ev_ms_map_init(struct EvMsMap *pevMap)
{
	memset(pevMap, 0, sizeof(struct EvMsMap));
	return 0;
}

struct EvMsNode* ev_ms_map_find(struct EvMsMap *pevMap, int fd)
{
    YG_ASSERT_RET(fd > 0, NULL);
	unsigned int hash = fd % EV_MS_SLOT_NUM;

	struct EvMsNode *pNode = pevMap->pList[hash];
	while(pNode != NULL) {
		if(pNode->sock == fd) {
            if(pNode->pSession->fd != fd) {
                YG_ERR("pSession->fd: %d != fd: %d", pNode->pSession->fd, fd);
                return NULL;

            }
			return pNode;
        }

		pNode = pNode->pnext;
	}

	return NULL;
}

void ev_ms_map_remove(struct EvMsMap *pevMap, int fd)
{
	YG_ASSERT_RET(fd > 0, );

	unsigned int hash = fd % EV_MS_SLOT_NUM;

	struct EvMsNode *pNode = pevMap->pList[hash], *pTmpNode = NULL;
	while(pNode != NULL) {
		if(pNode->sock == fd) {
			if(pTmpNode == NULL) {
				pevMap->pList[hash] = pNode->pnext;
			}
			else {
				pTmpNode->pnext = pNode->pnext;
			}

			free(pNode);
			return;
		}

		pTmpNode = pNode;
		pNode = pNode->pnext;
	}
}

int ev_ms_map_insert(struct EvMsMap *pevMap, int fd, struct EvSession *pSession)
{
	YG_ASSERT_RET(fd > 0, -1);

	struct EvMsNode *pNode = ev_ms_map_find(pevMap, fd);
	if(pNode != NULL) {
		YG_ERR("ev_ms_map_insert(%d) is exist map!", fd);
		ev_ms_map_remove(pevMap, fd);
	}

	pNode = ev_ms_node_new(fd, pSession);
	YG_ASSERT_RET(pNode != NULL, -1);

	int hash = fd % EV_MS_SLOT_NUM;
	pNode->pnext = pevMap->pList[hash];
	pevMap->pList[hash] = pNode;

	return 0;
}

void ev_ms_map_finit(struct EvMsMap *pevMap)
{
	struct EvMsNode *pNode, *pTmpNode;

	unsigned int i;
	for(i = 0; i < EV_MS_SLOT_NUM; i++) {
		pNode = pevMap->pList[i];
		while(pNode != NULL) {
			pTmpNode = pNode->pnext;

			struct EvSession *pSession = pNode->pSession;
			ev_session_free_exit(pSession);

			free(pNode);

			pNode = pTmpNode;
		}
	}
}

/*********************************************************************************
 *   ev_conf implement
 *********************************************************************************/
struct EvConf* ev_conf_get_empty_srv(struct EvSrv *pevSrv)
{
	struct EvConf *pSrvConf;

	unsigned int i;

	for(i = 0; i < pevSrv->srvNum; i++) {
		pSrvConf = &pevSrv->srvConfList[i];
		if(pSrvConf->isFree == 1) {
            pSrvConf->isFree = 0;
			return pSrvConf;
        }
	}


	if(pevSrv->srvNum >= BIND_IP_SIZE) {
		YG_ERR("(pevSrv->srvNum(%d) >= BIND_IP_SIZE", pevSrv->srvNum);
		return NULL;
	}


	pSrvConf = &pevSrv->srvConfList[pevSrv->srvNum];
	pevSrv->srvNum += 1;

	return pSrvConf;
}

struct EvConf* ev_conf_get_empty_cli(struct EvSrv *pevSrv)
{
	struct EvConf *pCliConf;

	unsigned int i;
	for(i = 0; i < pevSrv->cliNum; i++) {
		pCliConf = &pevSrv->cliConfList[i];
		if(pCliConf->isFree == 1) {
            pCliConf->isFree = 0;
			return pCliConf;
        }
	}

	if(pevSrv->cliNum >= MAX_CLIENT_SIZE) {
		YG_ERR("(pevSrv->cliNum(%d) >= MAX_CLIENT_SIZE", pevSrv->cliNum);
		return NULL;
	}

	pCliConf = &pevSrv->cliConfList[pevSrv->cliNum];
	pevSrv->cliNum += 1;

	return pCliConf;
}


void ev_conf_free(struct EvConf *pConf)
{
	memset(pConf, 0, sizeof(struct EvConf));
	pConf->isFree = 1;
}

/*********************************************************************************
 *   ev_srv implement
 *********************************************************************************/

int ev_srv_init(struct EvSrv *pevSrv)
{
    YG_ASSERT_RET(pevSrv != NULL, -1);

    pevSrv->srvNum = 0;
    pevSrv->evbase = (struct event_base *)event_init();
    YG_ASSERT_RET(pevSrv->evbase != NULL, -1);

    pevSrv->srvNum = 0;
    pevSrv->cliNum = 0;

    int iRet = ev_ms_map_init(&pevSrv->evMsMap);
    YG_ASSERT_RET(iRet == 0, -1);

    return 0;
}

int ev_srv_bind_fd(struct EvSrv *pevSrv, int sfd, const char *pip, unsigned int port,
		deal_accept_fun accept_fun, deal_pkg_fun pkg_fun, deal_close_fun close_fun,
		char isUdp, int timeout)
{
    YG_ASSERT_RET(pevSrv != NULL, -1);
    YG_ASSERT_RET(sfd > 0, -1);
    YG_ASSERT_RET(pip != NULL, -1);
    YG_ASSERT_RET(pkg_fun != NULL, -1);

    char isUnixSock = 0;
    if(port == 0) isUnixSock = 1;

    struct EvConf *pSrvConf = ev_conf_get_empty_srv(pevSrv);
    YG_ASSERT_RET(pSrvConf != NULL, -1);

    pSrvConf->psrv = pevSrv;
    pSrvConf->isUdp = isUdp;
    pSrvConf->isUnix = isUnixSock;
    pSrvConf->timeout = timeout;
    strncpy(pSrvConf->ip, pip, sizeof(pSrvConf->ip));
    pSrvConf->port = port;

    pSrvConf->pdeal_accept_fun = accept_fun;
    pSrvConf->pdeal_pkg_fun = pkg_fun;
    pSrvConf->pdeal_close_fun = close_fun;

    /* 将当前套结字申请会话 */
	unsigned int recvSize = isUdp ? 64 * 1024 : 8 * 1024;
	unsigned int sendSize = isUdp ? 64 * 1024 : 8 * 1024;
	struct EvSession *pSession = ev_session_new(pSrvConf, recvSize, sendSize);
	if(pSession == NULL) {
		YG_ERR("ev_session_new ERR!");
		ev_conf_free(pSrvConf);
		return -1;
	}

	int iRet = ev_ms_map_insert(&pevSrv->evMsMap, sfd, pSession);
	if (iRet < 0) {
		ev_conf_free(pSrvConf);
		ev_session_free(pSession);
		YG_ERR("ev_map_insert(%d) ERR!", sfd);
		return -1;
	}

	pSession->status = T_EV_LISTEN;
	pSession->fd = sfd;
	if (pip != NULL) {
		if(isUnixSock == 0) {
			bzero(&pSession->addr, sizeof(struct sockaddr_in));
			pSession->addr.sin_family = AF_INET;
			pSession->addr.sin_addr.s_addr = inet_addr(pip);
			pSession->addr.sin_port = htons(port);
		}
		else {
			bzero(&pSession->uaddr, sizeof(struct sockaddr_un));
			pSession->uaddr.sun_family = AF_UNIX;
			strcpy(pSession->uaddr.sun_path, pip);
		}
	}

	event_set(&pSession->rev, sfd, EV_READ | EV_PERSIST, ev_handler_accept, (void *)pSession);
	event_base_set(pevSrv->evbase, &pSession->rev);
	event_add(&pSession->rev, NULL);

    return 0;
}

int ev_srv_bind_ip(struct EvSrv *pevSrv, const char *pip,unsigned int port,
		deal_accept_fun accept_fun, deal_pkg_fun pkg_fun, deal_close_fun close_fun,
		char isUdp, int timeout, int listenNum)
{
	YG_ASSERT_RET(pip != NULL, -1);

	char isUnixSock = 0;
    if(port == 0) isUnixSock = 1;

	int sfd;
	if(isUnixSock == 0)
		sfd = yg_socket_tcpip_bind(pip, port, listenNum, 1);
	else
		sfd = yg_socket_unix_bind(pip, listenNum, 1);

	YG_ASSERT_RET(sfd > 0, -1);

	int iRet = ev_srv_bind_fd(pevSrv, sfd, pip, port, accept_fun, pkg_fun, close_fun, isUdp, timeout);
	if (iRet < 0) {
		close(sfd);
		return -1;
	}

	return sfd;
}

int ev_srv_connect_fd(struct EvSrv *pevSrv, int cfd, const char *pip, unsigned int port,
		deal_pkg_fun pkg_fun, deal_close_fun close_fun, char isUdp)
{
	YG_ASSERT_RET(pip != NULL, -1);
	YG_ASSERT_RET(cfd > 0, -1);

	char isUnixSock = 0;
    if(pip != NULL && port == 0) isUnixSock = 1;

	struct EvConf *pCliConf = ev_conf_get_empty_cli(pevSrv);;
	pCliConf->isUdp = isUdp;
	pCliConf->isUnix = isUnixSock;
    pCliConf->isCli = 1;
    pCliConf->psrv = pevSrv;
	memcpy(pCliConf->ip, pip, strlen(pip));
	pCliConf->port = port;
	pCliConf->pdeal_accept_fun = NULL;
	pCliConf->pdeal_pkg_fun = pkg_fun;
	pCliConf->pdeal_close_fun = close_fun;

	/* 将当前套结字申请会话 */
	unsigned int recvSize = isUdp ? 64 * 1024 : 8 * 1024;
	unsigned int sendSize = isUdp ? 64 * 1024 : 8 * 1024;
	struct EvSession *pSession = ev_session_new(pCliConf, recvSize, sendSize);
	if (pSession == NULL) {
		YG_ERR("ev_session_new ERR!");
		ev_conf_free(pCliConf);
		return -1;
	}

	int iRet = ev_ms_map_insert(&pevSrv->evMsMap, cfd, pSession);
	if(iRet < 0) {
		ev_session_free(pSession);
		ev_conf_free(pCliConf);
		YG_ERR("ev_map_insert(%d) ERR!", cfd);
		return -1;
	}

	pSession->status = T_EV_CONNED;
	pSession->fd = cfd;
	if(isUnixSock == 0) {
		bzero(&pSession->addr, sizeof(struct sockaddr_in));
		pSession->addr.sin_family = AF_INET;
		pSession->addr.sin_addr.s_addr = inet_addr(pip);
		pSession->addr.sin_port = htons(port);
	}
	else {
		bzero(&pSession->uaddr, sizeof(struct sockaddr_un));
		pSession->uaddr.sun_family = AF_UNIX;
		strcpy(pSession->uaddr.sun_path, pip);
	}
    event_set(&pSession->rev, cfd, EV_READ | EV_PERSIST, ev_handler_recv, (void *)pSession);
    event_set(&pSession->wev, cfd, EV_WRITE | EV_PERSIST, ev_handler_send, (void *)pSession);

    event_base_set(pevSrv->evbase, &pSession->rev);
    event_base_set(pevSrv->evbase, &pSession->wev);

    event_add(&pSession->rev, NULL);

    return 0;
}

int ev_srv_connect_ip(struct EvSrv *pevSrv, const char *pip, unsigned int port,
		deal_pkg_fun pkg_fun, deal_close_fun close_fun, char isUdp)
{
	YG_ASSERT_RET(pip != NULL, -1);

	char isUnixSock = 0;
    if(port == 0) isUnixSock = 1;

	int netType = isUdp == 0 ? T_NET_TCP : T_NET_UDP;
	int fd;
	if(isUnixSock == 1) {
		fd = yg_get_connect_unix(pip, netType, 1);
	}else {
		fd = yg_get_connect(pip, port, netType, 1);
	}
    YG_ASSERT_RET(fd > 0, -1);

	int iRet = ev_srv_connect_fd(pevSrv, fd, pip, port, pkg_fun, close_fun, isUdp);
	if(iRet < 0) {
		YG_ERR("ev_srv_connect_fd: %d, ip: %s, port: %d ERR!", fd, pip, port);
		close(fd);
		return -1;
	}

	return fd;
}

int ev_srv_run(struct EvSrv *pevSrv)
{
    YG_ASSERT_RET(pevSrv != NULL, -1);

    event_base_loop(pevSrv->evbase, 0);

    return 0;
}

void ev_srv_timer_deal(int fd, short event, void *args);

int ev_srv_add_timer(struct EvSrv *pevSrv, deal_timer_fun timer_fun, unsigned int tmval)
{
	struct EvSrvTimer *timerSrv = &pevSrv->tmSrv;
	if(timerSrv->tmval > 0) {
		evtimer_del(&timerSrv->tmev);
	}

	timerSrv->tmval = tmval;
	timerSrv->ptimer_fun = timer_fun;

	struct timeval tm = {tmval / 1000, tmval % 1000 };
	evtimer_set(&timerSrv->tmev, ev_srv_timer_deal, (void *)timerSrv);
    event_base_set(pevSrv->evbase, &timerSrv->tmev);
    evtimer_add(&timerSrv->tmev, &tm);

    return 0;
}

void ev_srv_timer_deal(int fd, short event, void *args)
{
	struct EvSrvTimer *timerSrv = (struct EvSrvTimer *)args;
	timerSrv->ptimer_fun();

	struct timeval tm = {timerSrv->tmval / 1000,timerSrv->tmval % 1000 };
	evtimer_add(&timerSrv->tmev, &tm);
}

void ev_srv_finit(struct EvSrv *pevSrv)
{
    ev_ms_map_finit(&pevSrv->evMsMap);

    if(pevSrv->evbase != NULL)
        event_base_free(pevSrv->evbase);
}

/*********************************************************************************
 *   event handler implement
 *********************************************************************************/
int ev_handler_accept_deal(struct EvSession *pSession, int sfd, short event);
int ev_handler_recv_deal_udp(struct EvSession *pSession, int sfd, short event);
int ev_handler_recv_deal_tcp(struct EvSession *pSession, int sfd, short event);

void ev_handler_accept(int sfd, short event, void *args)
{
    struct EvSession *pSession = (struct EvSession *)args;
    struct EvConf *pConf = pSession->conf;

    if(pConf->isUdp == 1)
        ev_handler_recv_deal_udp(pSession, sfd, event);
    else
        ev_handler_accept_deal(pSession, sfd, event);
}

void ev_handler_recv(int cfd, short event, void *args)
{
	struct EvSession *pSession = (struct EvSession *)args;
	struct EvConf *pConf = pSession->conf;

    YG_DBG("cfd(%d) event: %d", cfd, event);

	if (pConf->isUdp == 1)
		ev_handler_recv_deal_udp(pSession, cfd, event);
	else
		ev_handler_recv_deal_tcp(pSession, cfd, event);
}

void ev_handler_send(int cfd, short event, void *arg)
{
    YG_DBG("cfd(%d) event: %d", cfd, event);

    struct EvSession *pSession = (struct EvSession *)arg;
    struct EvBuf *pbuf = &pSession->evBuf;
    YG_ASSERT_RET(pbuf->pSendBuf != NULL, );

    int iLen = send(pSession->fd, pbuf->pSendBuf, pbuf->widx, 0);
    if(iLen < 0) {
        YG_ERR("send(%d) len(%d) ERR(%s)", pSession->fd, pbuf->widx, strerror(errno));
        if(iLen == -1 && errno == EAGAIN) return;
        ev_session_free(pSession);
        return;
    }

    YG_DBG("send: %d", iLen);

    if(iLen == 0) return;

    memmove(pbuf->pSendBuf, pbuf->pSendBuf + iLen, pbuf->widx - iLen);
    pbuf->widx -= iLen;

    if(pbuf->widx == 0)
        event_del(&pSession->wev);

    return;
}


int ev_handler_accept_deal(struct EvSession *pSession, int sfd, short event)
{
    YG_DBG("fd(%d) recv accept, event: %d", sfd, event);

	int iRet;
    struct EvConf *pConf = pSession->conf;
    struct EvSrv *pevSrv = pConf->psrv;

    struct sockaddr_in in_addr;
    struct sockaddr_un un_addr;

    char isUnixSock = pConf->isUnix;
    struct sockaddr *pAddr = isUnixSock ? (struct sockaddr *)&un_addr : (struct sockaddr *)&in_addr;
    unsigned int addrLen = isUnixSock ? sizeof(un_addr) : sizeof(in_addr);

    int cfd = accept(sfd, (struct sockaddr *)pAddr, &addrLen);
    if(cfd == -1) {
        YG_ERR("accept(%d) err(%s)", sfd, strerror(errno));
        return -1;
    }

    YG_DBG("sfd(%d) accept(%d)", sfd, cfd);

    int iflags = fcntl(cfd, F_GETFL);
    iRet = fcntl(cfd, F_SETFL, iflags | O_NONBLOCK);
    if(iRet < 0) {
        YG_ERR("fcntl(%d) ERR(%s)", cfd, strerror(errno));
        close(cfd);
        return -1;
    }

	struct EvSession *pCliSession = ev_session_new(pConf, 8 * 1024, 4 * 1024);
	if(pCliSession == NULL) {
		YG_ERR("ev_session_new ERR!");
		close(cfd);
		return -1;
	}

	iRet = ev_ms_map_insert(&pevSrv->evMsMap, cfd, pCliSession);
	if(iRet < 0) {
		ev_session_free(pCliSession);
		YG_ERR("ev_map_insert(%d) ERR!", cfd);
		return -1;
	}

	pCliSession->status = T_EV_CONNED;
	pCliSession->fd = cfd;
    if(isUnixSock)
    	memcpy(&pCliSession->uaddr, &un_addr, sizeof(un_addr));
    else
    	memcpy(&pCliSession->addr, &in_addr, sizeof(in_addr));
    
    event_set(&pCliSession->rev, cfd, EV_READ | EV_PERSIST, ev_handler_recv, (void *)pCliSession);
    event_set(&pCliSession->wev, cfd, EV_WRITE | EV_PERSIST, ev_handler_send, (void *)pCliSession);

    event_base_set(pevSrv->evbase, &pCliSession->rev);
    event_base_set(pevSrv->evbase, &pCliSession->wev);

    event_add(&pCliSession->rev, NULL);

    
    if(pConf->pdeal_accept_fun != NULL) {
    	iRet = pConf->pdeal_accept_fun(sfd, cfd, pAddr, addrLen);
    	if(iRet < 0) {
    		YG_ERR("logic pdeal_accept_fun(%d) ERR(%d)", cfd, iRet);
    		ev_session_free(pCliSession);
    		return -1;
    	}
    }

    return 0;
}

int ev_handler_recv_deal_udp(struct EvSession *pSession, int sfd, short event)
{
    YG_ASSERT_RET(pSession != NULL, -1);
    YG_ASSERT_RET(pSession->conf != NULL, -1);

    struct EvBuf *pbuf = &pSession->evBuf;
    YG_ASSERT_RET(pbuf->pRecvBuf != NULL, -1);

    struct sockaddr *paddr = pSession->conf->isUnix ? (struct sockaddr *)&pSession->addr : (struct sockaddr *)&pSession->uaddr;
    unsigned int cliAddrLen = pSession->conf->isUnix ? sizeof(pSession->addr) : sizeof(pSession->uaddr);
    int iLen = recvfrom(sfd, pbuf->pRecvBuf, pbuf->recvSize, 0, paddr, &cliAddrLen);
    if(iLen <= 0) {
        YG_ERR("recvfrom(%d) ERR(%s)", sfd, strerror(errno));
        if(iLen == -1 && errno == EAGAIN) return 0;
        ev_session_free(pSession);
        return -1;
    }

    /* 解包 */
    int packLen = yg_packet_head_unpack(&pSession->netHead, pbuf->pRecvBuf, iLen);
    YG_ASSERT_RET(packLen >= 0, -1);

    int iRet = pSession->conf->pdeal_pkg_fun(pSession->fd, paddr, cliAddrLen, pbuf->pRecvBuf + packLen, iLen - packLen, pSession->netHead.ucType);
    return iRet;
}

int ev_handler_recv_deal_tcp(struct EvSession *pSession, int sfd, short event)
{
    int iRet;

    YG_ASSERT_RET(pSession != NULL, -1);
    YG_ASSERT_RET(pSession->conf != NULL, -1);

    struct EvBuf *pbuf = &pSession->evBuf;
    YG_ASSERT_RET(pbuf->pRecvBuf != NULL, -1);

    int iLen = recv(pSession->fd, pbuf->pRecvBuf + pbuf->ridx, pbuf->recvSize - pbuf->ridx, 0);
    if(iLen <= 0) {
        if (iLen < 0)
            YG_ERR("recv(%d) ERR(%s)", pSession->fd, strerror(errno));
        if(iLen == -1 && errno == EAGAIN) return;
        ev_session_free(pSession);
        return;
    }

    pbuf->ridx += iLen;
    YG_DBG("recv: %d, ridx: %d", iLen, pbuf->ridx);
	
    while(pbuf->ridx > 0) {	
		if(pbuf->pkgLen == 0)
        {
            if(pbuf->ridx < sizeof(struct NetHead)) return 0;
            int packLen = yg_packet_head_unpack(&pSession->netHead, pbuf->pRecvBuf, sizeof(struct NetHead));
            if(packLen <= 0) {
                YG_ERR("ev_req_head(ucStart: %d, pkgLen: %d, ucType: (%d) is not valid!", pSession->netHead.ucStart, pSession->netHead.uPkgLen, pSession->netHead.ucType);
                ev_session_free(pSession);
                return -1;
            }

            pbuf->pkgLen = pSession->netHead.uPkgLen;
			
            iRet = ev_buf_recv_check(pbuf);
            if(iRet != 0) {
                ev_session_free(pSession);
                return 0;
            }

        }

        if(pbuf->ridx < pbuf->pkgLen) return 0;

        struct sockaddr *paddr = pSession->conf->isUnix ? (struct sockaddr *)&pSession->addr : (struct sockaddr *)&pSession->uaddr;
        unsigned int cliAddrLen = pSession->conf->isUnix ? sizeof(pSession->addr) : sizeof(pSession->uaddr);


        iRet = pSession->conf->pdeal_pkg_fun(pSession->fd, paddr, cliAddrLen,pbuf->pRecvBuf + sizeof(struct NetHead), pbuf->pkgLen - sizeof(struct NetHead),pSession->netHead.ucType);
        if(iRet < 0) {
            YG_ERR("pdeal_pkg_fun ERR");
        }

        pbuf->ridx -= pbuf->pkgLen;
        if(pbuf->ridx > 0) 
            memmove(pbuf->pRecvBuf, pbuf->pRecvBuf + pbuf->pkgLen, pbuf->ridx);
        pbuf->pkgLen = 0;

        if(pbuf->ridx == 0) break;
    }

    return 0;
}



int ev_fd_send_udp(int fd, const char *pcnt, unsigned int cntLen, unsigned char headType, struct sockaddr *addr, unsigned int addrLen);
int ev_session_send_tcp(struct EvSession *pSession,
		const char *pcnt, unsigned int cntLen, unsigned char headType);

/* 对于服务端, send client use udp must point addr */
int ev_session_send_udp(struct EvSession *pSession, struct sockaddr *addr, unsigned int addrLen,
		const char *pcnt, unsigned int cntLen, unsigned char headType)
{
	YG_ASSERT_RET(pSession != NULL, -1);
	YG_ASSERT_RET(pSession->conf != NULL, -1);
    YG_ASSERT_RET(pcnt != NULL, -1);
    YG_ASSERT_RET(cntLen > 0, -1);
    YG_ASSERT_RET(addr != NULL, -1);

	if(pSession->conf->isUnix && addrLen != sizeof(struct sockaddr_un)) {
		YG_ERR("unix must soackaddr_un");
		return -1;
	}

	return ev_fd_send_udp(pSession->fd, pcnt, cntLen, headType, addr, addrLen);
}

int ev_session_send(struct EvSession *pSession,
		const char *pcnt, unsigned int cntLen, unsigned char headType)
{
	YG_ASSERT_RET(pSession != NULL, -1);
	YG_ASSERT_RET(pSession->conf != NULL, -1);
    YG_ASSERT_RET(pcnt != NULL, -1);
    YG_ASSERT_RET(cntLen > 0, -1);

	if(pSession->conf->isUdp) {
		if(pSession->conf->isCli == 0) {
			YG_ERR("srv sock udp must ponit dest addr!");
			return -1;
		}

		struct sockaddr *paddr = pSession->conf->isUnix ? (struct sockaddr *)&pSession->uaddr : (struct sockaddr *)&pSession->addr;
		unsigned int addrLen = pSession->conf->isUnix ? sizeof(pSession->uaddr) : sizeof(pSession->addr);
		return ev_session_send_udp(pSession, paddr, addrLen, pcnt, cntLen, headType);
	}
	else {
		return ev_session_send_tcp(pSession, pcnt, cntLen, headType);
	}
}

int ev_srv_send(struct EvSrv *pevSrv, int fd,
		const char *pcnt, unsigned int cntLen, unsigned char headType)
{
    YG_ASSERT_RET(fd > 0, -1);
    YG_ASSERT_RET(pcnt != NULL, -1);
    YG_ASSERT_RET(cntLen > 0, -1);

	struct EvMsNode *pNode = ev_ms_map_find(&pevSrv->evMsMap, fd);
	if(pNode == NULL) {
		YG_ERR("sock; %d is not exist Session!", fd);
		return -1;
	}

	struct EvSession *pSession = pNode->pSession;
	YG_ASSERT_RET(pSession != NULL, -1);

	return ev_session_send(pSession, pcnt, cntLen, headType);
}

int ev_srv_send_udp(struct EvSrv *pevSrv, int fd, struct sockaddr *addr, unsigned int addrLen,
		const char *pcnt, unsigned int cntLen, unsigned char headType)
{
    YG_ASSERT_RET(fd > 0, -1);
    YG_ASSERT_RET(addr != NULL, -1);
    YG_ASSERT_RET(pcnt != NULL, -1);
    YG_ASSERT_RET(cntLen > 0, -1);

	struct EvMsNode *pNode = ev_ms_map_find(&pevSrv->evMsMap, fd);
	if(pNode == NULL) {
		YG_ERR("sock; %d is not exist Session!", fd);
		return -1;
	}

	struct EvSession *pSession = pNode->pSession;
	YG_ASSERT_RET(pSession != NULL, -1);

	return ev_session_send_udp(pSession, addr,addrLen, pcnt, cntLen, headType);
}

int ev_session_send_tcp(struct EvSession *pSession,
		const char *pcnt, unsigned int cntLen, unsigned char headType)
{
    int iRet;

    struct EvBuf *pbuf = &pSession->evBuf;
    YG_ASSERT_RET(pbuf->pSendBuf != NULL, -1);

    char headBuf[sizeof(struct NetHead)];
    int sendSize = cntLen + sizeof(struct NetHead);
	struct NetHead netHead;
	netHead.uPkgLen = sendSize;
	netHead.ucStart = NET_START_SIGN;
	netHead.ucType = headType;
	int headLen = yg_packet_head_pack(&netHead, headBuf, sizeof(headBuf));
	if(headLen != sizeof(struct NetHead)) {
		YG_ERR("yg_packet_head_pack ERR!");
		return -1;
	}

    iRet = ev_buf_send_check(pbuf, sendSize);
    YG_ASSERT_RET(iRet == 0, -1);

    memcpy(pbuf->pSendBuf + pbuf->widx, headBuf, sizeof(headBuf));  pbuf->widx += sizeof(headBuf);
    memcpy(pbuf->pSendBuf + pbuf->widx, pcnt, cntLen);				pbuf->widx += cntLen;

    YG_DBG("entry!");
    event_add(&pSession->wev, NULL);

    return 0;

}

int ev_fd_send_udp(int fd, const char *pcnt, unsigned int cntLen, unsigned char headType, struct sockaddr *addr, unsigned int addrLen)
{
    YG_ASSERT_RET(fd > 0, -1);

	unsigned int bufSize = cntLen + sizeof(struct NetHead);
	char *pbuf = (char *)malloc(bufSize);
	if(pbuf == NULL) {
		YG_ERR("malloc(%d) ERR(%s)", bufSize, strerror(errno));
		return -1;
	}

	struct NetHead netHead;
	netHead.uPkgLen = bufSize;
	netHead.ucStart = NET_START_SIGN;
	netHead.ucType = headType;
	int headLen = yg_packet_head_pack(&netHead, pbuf, bufSize);
	if(headLen != sizeof(struct NetHead)) {
		free(pbuf);
		YG_ERR("yg_packet_head_pack ERR!");
		return -1;
	}

	memcpy(pbuf + headLen, pcnt, cntLen);

    int iLen = sendto(fd, pbuf, bufSize, 0, addr, addrLen);
    free(pbuf);
    if(iLen != bufSize) {
        YG_ERR("sendto(%d) len(%d) ERR(%s)", fd, cntLen, strerror(errno));
        return -1;
    }

    return 0;
}

int ev_srv_free(struct EvSrv *pevSrv, int fd)
{
    YG_ASSERT_RET(fd >= 0, -1);

	struct EvMsNode *pNode = ev_ms_map_find(&pevSrv->evMsMap, fd);
	if(pNode == NULL) {
		YG_ERR("sock; %d is not exist Session!", fd);
		return -1;
	}

	struct EvSession *pSession = pNode->pSession;
	YG_ASSERT_RET(pSession != NULL, -1);

    ev_session_free(pSession);

    return 0;
}
