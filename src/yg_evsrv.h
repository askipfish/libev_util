/***********************************************************************
 * File : yg_evsrv.h
 * Brief: 
 * 
 * History
 * ---------------------------------------------------------------------
 * 2016-06-15     guichunpeng   1.0    created
 * 
 ***********************************************************************
 */

#ifndef  YG_EVSRV_INC
#define  YG_EVSRV_INC

#include "yg_assert.h"
#include "event.h"
#include "yg_net.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define BUFF_RECV_SIZE (8 * 1024)
#define BUFF_SEND_SIZE (8 * 1024)


struct EvBuf
{
    unsigned char *pRecvBuf;
    unsigned char *pSendBuf;

    unsigned int recvSize;
    unsigned int sendSize;

    unsigned int ridx;
    unsigned int widx;

    unsigned int pkgLen;
};

struct EvSrv;
struct EvConf;
struct EvSession;

/* 外围千万不要关闭sock, 框架会关闭！！！！！！ */ 
typedef int deal_pkg_fun(int sock, struct sockaddr *addr, unsigned int addrLen, const char *pkg, unsigned int pkegLen, unsigned int headCmd);
typedef int deal_accept_fun(int srvsock, int sock, struct sockaddr *addr, int addrLen);
typedef int deal_close_fun(int sock);
typedef int deal_timer_fun();

enum EvStatus
{
	T_EV_UNUSED   	= 0x0,
	T_EV_LISTEN		= 0x1,
	T_EV_CONNED		= 0x2,
	T_EV_CLOSE		= 0x3
};

struct EvSession
{
	enum EvStatus status;

	int fd;
    struct event rev;
    struct event wev;
    struct EvBuf evBuf;

    struct EvConf *conf;
    struct NetHead netHead;
    struct sockaddr_in addr;
    struct sockaddr_un uaddr;
};

struct EvConf
{
	char isFree;
	char isCli;       		/*  是否是客户端 */
    char isUdp;				/* 是否是Udp */
    char isUnix;			/* 是否是unix 套结字 */
    char ip[512];         	/* add for unix */
    unsigned int port;
    int timeout;

    deal_accept_fun *pdeal_accept_fun;
    deal_pkg_fun *pdeal_pkg_fun;
    deal_close_fun *pdeal_close_fun;

    struct EvSrv *psrv;
};

struct EvSrvTimer
{
	struct event tmev;
	unsigned int tmval;
	deal_timer_fun *ptimer_fun;
};

/* 用于协助快速通过 sock 定位到session */
struct EvMsNode
{
	int sock;
	struct EvSession *pSession;
	struct EvMsNode *pnext;
};

#define EV_MS_SLOT_NUM 10240
struct EvMsMap
{
	struct EvMsNode *pList[EV_MS_SLOT_NUM];
};

#define BIND_IP_SIZE (16)
#define MAX_CLIENT_SIZE (64)

struct EvSrv
{
    struct event_base *evbase; 

    /* 服务端 */
    struct EvConf srvConfList[BIND_IP_SIZE];
    unsigned int srvNum;

    /* 客户端 */
    struct EvConf cliConfList[MAX_CLIENT_SIZE]; 
    unsigned int cliNum;

    struct EvSrvTimer tmSrv;
    struct EvMsMap evMsMap;
};


/*********************************************************************************
 *   接口
 *********************************************************************************/


int ev_srv_init(struct EvSrv *pevSrv);
int ev_srv_add_timer(struct EvSrv *pevSrv, deal_timer_fun timer_fun, unsigned int tmval);
int ev_srv_run(struct EvSrv *pevSrv);
void ev_srv_finit(struct EvSrv *pevSrv);

/* ip 以/ 开始则认为是unix socket */
int ev_srv_bind_fd(struct EvSrv *pevSrv, int sfd, const char *pip, unsigned int port,
		deal_accept_fun accept_fun, deal_pkg_fun pkg_fun, deal_close_fun close_fun,
		char isUdp, int timeout);

int ev_srv_bind_ip(struct EvSrv *pevSrv, const char *pip,unsigned int port,
		deal_accept_fun accept_fun, deal_pkg_fun pkg_fun, deal_close_fun close_fun,
		char isUdp, int timeout, int listenNum);


int ev_srv_connect_fd(struct EvSrv *pevSrv, int cfd, const char *pip, unsigned int port,
		deal_pkg_fun pkg_fun, deal_close_fun close_fun, char isUdp);

int ev_srv_connect_ip(struct EvSrv *pevSrv, const char *pip, unsigned int port,
		deal_pkg_fun pkg_fun, deal_close_fun close_fun, char isUdp);




int ev_session_send(struct EvSession *pSession,
		const char *pcnt, unsigned int cntLen, unsigned char headType);

int ev_srv_send(struct EvSrv *pevSrv, int fd,
		const char *pcnt, unsigned int cntLen, unsigned char headType);

/* 对于服务端, send client use udp must point addr */
int ev_session_send_udp(struct EvSession *pSession, struct sockaddr *addr, unsigned int addrLen,
		const char *pcnt, unsigned int cntLen, unsigned char headType);

int ev_srv_send_udp(struct EvSrv *pevSrv, int fd, struct sockaddr *addr, unsigned int addrLen,
		const char *pcnt, unsigned int cntLen, unsigned char headType);


int ev_srv_free(struct EvSrv *pevSrv, int fd);



#endif   /* ----- #ifndef YG_EVSRV_INC  ----- */

