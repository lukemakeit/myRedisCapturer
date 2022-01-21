## redis抓包工具 myRedisCapture
redis可通过`monitor`命令获取执行的命令.  
但大部分redis proxy并不支持monitor命令,抓包请求命令与来源ip对于proxy来说是一个非常常见的需求，且在定位问题时使用非常频繁。 
该工具通过libpcap库完成网络抓包,同时根据resp格式解析请求命令，将命令进行输出。

### 环境介绍
- Tlinux 2.2+
- CMake 3.13.0+
- C++ 17

### 编译二进制
```shell
cd build
cmake ..
make
```

### 参数说明
- `--device`: 网络设备名称,如`eth1`、`eth0`、`lo`等;
- `--port`:目标端口号,用于过滤网络包,如`--port=30000`;
- `--ip`:目标ip,用于过滤网络包,如`--ip=127.0.0.1`;
- `--timeout`: 请求抓取时间,单位秒.默认0,无限制;
- `--output-file`: 结果输出到文件,如果为空则标准输出.
- `--log-file`: 错误日志保存的路径,默认`./capture.log`.
- `--threads`: 解析线程个数,默认4个线程.
- `--only-big-req`: 默认为0,打印所有命令.如果`--only-big-req`大于0,则只抓取 pipeline命令数大于`--only-big-req`，`mget`、`mset`等操作的key个数超过`--only-big-req`的命令;
- `--only-big-val`: 默认为0,打印所有命令.如果`--only-big-val`大于0,则只抓取命令中存在value大于`--only-big-val`的命令.单位byte;

### 使用注意事项
1. 用`root`账户执行;
2. 该工具无法完整捕获命令,特别在qps 10w/s+ or value特别大时,捕获的请求情况和实际执行的请求情况会有较大差距;


### 使用示例
```sh
#示例1:打印所有命令到 1.log
./myRedisCapture --device=eth1 --ip=127.0.0.1 --port=6379 --timeout=30 --output-file=1.log

#示例2:只打印val大于3000 bytes的命令
./myRedisCapture --device=eth1 --ip=127.0.0.1 --port=6379 --timeout=30 --only-big-val=3000

#示例3:只打印pipeline中命令个数超过 100 or keys个数超过 100的命令
./myRedisCapture --device=eth1 --ip=127.0.0.1 --port=6379 --timeout=30 --only-big-req=100
```
### 结果示例
![example01](./img/example01.png)

### 关于libpcap
关于libpcap的使用建议参考:
- [TCPDUMP libpcap](https://www.tcpdump.org/pcap.html)
- [Using libpcap in C](https://www.devdungeon.com/content/using-libpcap-c#pcap-loop)
- [Offline packet capture analysis with C/C++ & libpcap](http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/)
- [How to code a Packet Sniffer in C with Libpcap on Linux](https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/)