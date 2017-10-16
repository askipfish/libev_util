在libevent 上封装一个简单网络库，方便构建 TCP/UDP/UNIX 服务端，和客户端。
1. 支持长连接和短连接。
2. 服务端可以支持每妙处理请求，5W/qps， 每核。
3. 信息接收采用预分配加动态调整，性能和内存取得很好的平衡。
4. 支持定时回调上层逻辑

接口例子：

void test_tcp_srv()
{
    const char *ip = "127.0.0.1";
    unsigned int port = 1235;

    ev_srv_init(&evSrv);
    
    int iRet = ev_srv_bind_ip(&evSrv, ip, port, ts_accept_fun, ts_pkg_fun, ts_close_fun, 0, -1, 5);// 回调
    YG_ASSERT_RET(iRet > 0, );

    iRet = ev_srv_add_timer(&evSrv, ts_timer_fun, 1000 * 3); // 3s回调，便于执行定时操作
    YG_ASSERT_RET(iRet >= 0, );

    ev_srv_run(&evSrv);
}



测试：
1.  编译测试 cd test; make;
2.  启动测试服务端 ./test_ev tcp_srv;
3.  启动测试客户端  ./test_ev tcp_cli;
	


