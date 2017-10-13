/*
 * =====================================================================================
 *
 *       Filename:  test_net.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年06月22日 10时27分33秒 CST
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:   (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <time.h>
extern "C"
{
#include "yg_evsrv.h"
}

struct EvSrv evSrv;
char isUdp = 0;

int ts_accept_fun(int sfd, int cfd, struct sockaddr *addr, int addrLen)
{
    fprintf(stderr, "[srv] accept srv_fd: %d,  cli_fd: %d, addrLen: %d\n", sfd, cfd, addrLen);

    return 0;
}

int ts_pkg_fun(int sock, struct sockaddr *addr, unsigned int addrLen, const char *pkg, unsigned int pkgLen, unsigned int headCmd)
{
    static int cc = 0;
    fprintf(stderr, "[srv] sock: %d, pkg: %s, pkg_len: %d, head_cmd: %d\n", sock, pkg, pkgLen, headCmd);

    char pcnt[512];
    snprintf(pcnt, sizeof(pcnt) - 1, "Yes I recv msg count: %d", cc);
    cc += 1;

    sleep(2);

    int iLen;
    if(isUdp == 0)
        iLen = ev_srv_send(&evSrv, sock, pcnt, strlen(pcnt), 0);
    else {
        iLen =  ev_srv_send_udp(&evSrv, sock, addr, addrLen, pcnt, strlen(pcnt), 0);
    }
        
    return 0;
}

int ts_close_fun(int sock)
{
    fprintf(stderr, "[srv] cli sock: %d close\n", sock);
    return 0;
}

int ts_timer_fun()
{
    fprintf(stderr, "[srv] timer exec, time: %d\n", time(NULL));
    return 0;
}

int tCliSock = 0;
int tc_pkg_fun(int sock, struct sockaddr *addr, unsigned int addrLen, const char *pkg, unsigned int pkgLen, unsigned int headCmd)
{
    fprintf(stderr, "[cli] sock: %d, pkg: %s, pkg_len: %d, head_cmd: %d\n", sock, pkg, pkgLen, headCmd);
    return 0;
}

int tc_close_fun(int sock)
{
    fprintf(stderr, "[cli] sock: %d close\n", sock);
    tCliSock = 0;
    return 0;
}

int tc_timer_fun()
{
    static int count = 3;
    fprintf(stderr, "[cli]timer exec, time: %d\n", time(NULL));
    if(tCliSock > 0 && count > 0) {
        char pcnt[32];
        snprintf(pcnt, sizeof(pcnt), "%s_%d", "hello server, I'm client", count);
        int iLen = ev_srv_send(&evSrv, tCliSock, pcnt, strlen(pcnt), 0);
        fprintf(stderr, "[cli] send_len: %d\n", strlen(pcnt));

        count -= 1;
        if(count == 0) {
            fprintf(stderr, "[cli] I exec exit!\n");
            ev_srv_free(&evSrv, tCliSock);
            exit(0);
        }
    }
    return 0;
}


void test_tcp_srv()
{
    const char *ip = "127.0.0.1";
    unsigned int port = 1235;

    ev_srv_init(&evSrv);

    int iRet = ev_srv_bind_ip(&evSrv, ip, port, ts_accept_fun, ts_pkg_fun, ts_close_fun, 0, -1, 5);
    YG_ASSERT_RET(iRet > 0, );

    iRet = ev_srv_add_timer(&evSrv, ts_timer_fun, 1000 * 3);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void test_udp_srv()
{
    const char *ip = "127.0.0.1";
    unsigned int port = 1235;
    isUdp = 1;

    ev_srv_init(&evSrv);

    int iRet = ev_srv_bind_ip(&evSrv, ip, port, ts_accept_fun, ts_pkg_fun, ts_close_fun, 1, -1, 0);
    YG_ASSERT_RET(iRet > 0, );

    iRet = ev_srv_add_timer(&evSrv, ts_timer_fun, 1000 * 3);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void test_tcp_cli()
{
    const char *ip = "127.0.0.1";
    unsigned int port = 1235;

    ev_srv_init(&evSrv);

    int iRet = ev_srv_connect_ip(&evSrv, ip, port, tc_pkg_fun, tc_close_fun, 0);
    YG_ASSERT_RET(iRet > 0, );

    tCliSock = iRet;

    iRet = ev_srv_add_timer(&evSrv, tc_timer_fun, 1000 * 3);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void test_udp_cli()
{
    const char *ip = "127.0.0.1";
    unsigned int port = 1235;
    isUdp = 1;

    ev_srv_init(&evSrv);

    int iRet = ev_srv_connect_ip(&evSrv, ip, port, tc_pkg_fun, tc_close_fun, 1);
    YG_ASSERT_RET(iRet > 0, );

    tCliSock = iRet;

    iRet = ev_srv_add_timer(&evSrv, tc_timer_fun, 1000 * 3);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void test_unix_srv()
{
    const char *path = "./test_socket";

    ev_srv_init(&evSrv);

    int iRet = ev_srv_bind_ip(&evSrv, path, 0, ts_accept_fun, ts_pkg_fun, ts_close_fun, 0, -1, 5);
    YG_ASSERT_RET(iRet > 0, );

    iRet = ev_srv_add_timer(&evSrv, ts_timer_fun, 1000 * 10);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void test_unix_cli()
{
    const char *path = "./test_socket";

    ev_srv_init(&evSrv);

    int iRet = ev_srv_connect_ip(&evSrv, path, 0, tc_pkg_fun, tc_close_fun, 0);
    YG_ASSERT_RET(iRet > 0, );

    tCliSock = iRet;

    iRet = ev_srv_add_timer(&evSrv, tc_timer_fun, 1000 * 3);
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}

void usage(const char *exe)
{
    fprintf(stderr, "Usage: %s tcp_srv|tcp_cli|udp_srv|udp_cli|unix_srv|unix_cli\r\n", exe);
    exit(-1);
}

int main(int argc, char *argv[])
{
    if(argc < 2) {
        usage(argv[0]);
    }

    if(strcmp(argv[1], "tcp_srv") == 0)
        test_tcp_srv();
    if(strcmp(argv[1], "tcp_cli") == 0)
        test_tcp_cli();
    if(strcmp(argv[1], "udp_srv") == 0)
        test_udp_srv();
    if(strcmp(argv[1], "udp_cli") == 0)
        test_udp_cli();
    else if(strcmp(argv[1], "unix_srv") == 0)
        test_unix_srv();
    else if(strcmp(argv[1], "unix_cli") == 0)
        test_unix_cli();
    else {
        YG_ERR("arg: %s not valid!", argv[1]);
        usage(argv[0]);
    }

    return 0;
}

