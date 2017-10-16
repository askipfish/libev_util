在libevent 上封装一个简单网络库，方便构建 TCP/UDP/UNIX 服务端，和客户端。
1. 支持长连接和短连接。
2. 服务端可以支持每妙处理请求，5W/qps， 每核。
3. 信息接收采用预分配加动态调整，性能和内存取得很好的平衡。
4. 支持定时回调上层逻辑

接口例子：
<p>int ts_accept_fun(int sfd, int cfd, struct sockaddr *addr, int addrLen)<br/>
{<br/>
    fprintf(stderr, &quot;[srv] accept srv_fd: %d,  cli_fd: %d, addrLen: %d\n&quot;, sfd, cfd, addrLen);<br/>
    return 0;<br/>
}</p>

<p>// pkg 是个完整的应用层协议包，headCmd 是客户端用来标示pkg解包协议<br/>
int ts_pkg_fun(int sock, struct sockaddr *addr, unsigned int addrLen, const char *pkg, unsigned int pkgLen, unsigned int headCmd)<br/>
{<br/>
    fprintf(stderr, &quot;[srv] sock: %d, pkg: %s, pkg_len: %d, head_cmd: %d\n&quot;, sock, pkg, pkgLen, headCmd);<br/><br/>
    return 0;<br/>
}</p>

<p>int ts_close_fun(int sock)<br/>
{<br/>
    fprintf(stderr, &quot;[srv] cli sock: %d close\n&quot;, sock);<br/>
    return 0;<br/>
}</p>

<p>int ts_timer_fun()<br/>
{<br/>
    fprintf(stderr, &quot;[srv] timer exec, time: %d\n&quot;, time(NULL));<br/>
    return 0;<br/>
}</p>

<p>void test_tcp_srv()<br/>
{<br/>
    const char *ip = &quot;127.0.0.1&quot;;<br/>
    unsigned int port = 1235;<br/>
    ev_srv_init(&amp;evSrv);<br/>
    int iRet = ev_srv_bind_ip(&amp;evSrv, ip, port, ts_accept_fun, ts_pkg_fun, ts_close_fun, 0, -1, 5);<br/>
    YG_ASSERT_RET(iRet &gt; 0, );<br/>
    iRet = ev_srv_add_timer(&amp;evSrv, ts_timer_fun, 1000 * 3); <br/>
    YG_ASSERT_RET(iRet &gt;= 0, );<br/>
    ev_srv_run(&amp;evSrv);<br/>
}</p>



测试：
1.  编译测试 cd test; make;
2.  启动测试服务端 ./test_ev tcp_srv;
3.  启动测试客户端  ./test_ev tcp_cli;
	


