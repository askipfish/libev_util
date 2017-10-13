在libevent 上封装一个简单网络库，方便构建 TCP/UDP/UNIX 服务端，和客户端。
1. 支持长连接和短连接。
2. 服务端可以支持每妙处理请求，5W/qps， 每核。
3. 信息接收采用预分配加动态调整，性能和内存取得很好的平衡。
4. 支持定时回调上层逻辑


测试：
        cd test; make; 
        ./test_ev tcp_srv;
        ./test_ev tcp_cli;
	


