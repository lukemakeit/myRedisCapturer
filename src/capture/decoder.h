#ifndef _MY_REDIS_CAPTURE_DECODER_H
#define _MY_REDIS_CAPTURE_DECODER_H

#include <time.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

struct CmdItem {
  long multiCnt;     // set a 1, multiCnt is 3
  long bulkLen;      // $3\r\nset\r\n,bulkLen is 3
  char msgType;      // '*' or '$'
  long maxArgvSize;  // the max size of argvs in the command

  std::vector<std::string> cmdArgs;
  std::vector<std::string> cmdKeys;
  std::string maxKey;
  int keyCnt;
  std::string maxVal;
  int ValCnt;
};

class RedisAofDecoder {
 public:
  RedisAofDecoder(std::string &&srcIP, int &&srcPort, std::string &&dstIP,
                  int &&dstPort, std::string &&payload, time_t t)
      : _src_ip(srcIP),
        _src_port(srcPort),
        _dst_ip(dstIP),
        _dst_port(dstPort),
        _payload(payload),
        _req_time(t) {}
  RedisAofDecoder(const RedisAofDecoder &) = delete;
  RedisAofDecoder(RedisAofDecoder &&) = delete;

  const std::string &getSrcIP() const { return _src_ip; }
  int getSrcPort() const { return _src_port; }
  const std::string &getDstIP() const { return _dst_ip; }
  int getDstPort() const { return _dst_port; }
  time_t getReqTime() const { return _req_time; }
  const std::shared_ptr<std::string> getError() const { return _err; }
  std::vector<std::shared_ptr<CmdItem>> &getAllCmds() { return _reqCmds; };

  int run();

 private:
  std::string _src_ip;
  int _src_port;
  std::string _dst_ip;
  int _dst_port;
  std::string _payload;
  time_t _req_time;
  std::shared_ptr<std::string> _err;

  std::vector<std::shared_ptr<CmdItem>> _reqCmds;
};

#endif