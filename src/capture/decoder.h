// Copyright [2022] <Copyright lukexwang@tencent.com>

#ifndef MYREDISCAPTURER_CAPTURE_DECODER_H_
#define MYREDISCAPTURER_CAPTURE_DECODER_H_

#include <time.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

struct CmdItem {
  int multiCnt;     // set a 1, multiCnt is 3
  int bulkLen;      // $3\r\nset\r\n,bulkLen is 3
  char msgType;     // '*' or '$'
  int maxArgvSize;  // the max size of argvs in the command

  std::vector<std::string> cmdArgs;
  std::vector<std::string> cmdKeys;
  std::string maxKey;
  int keyCnt;
  std::string maxVal;
  int ValCnt;
  bool unknown_cmd;
};

class RedisAofDecoder {
 public:
  RedisAofDecoder(std::string &&srcIP, int srcPort, std::string &&dstIP,
                  int dstPort, std::string &&one_req_payload, timeval t)
      : _src_ip(srcIP),
        _src_port(srcPort),
        _dst_ip(dstIP),
        _dst_port(dstPort),
        _req_all_payloads(one_req_payload),
        _req_time(t) {}
  RedisAofDecoder(const RedisAofDecoder &) = delete;
  RedisAofDecoder(RedisAofDecoder &&) = delete;

  const std::string &getSrcIP() const { return _src_ip; }
  int getSrcPort() const { return _src_port; }
  const std::string &getDstIP() const { return _dst_ip; }
  int getDstPort() const { return _dst_port; }
  timeval getReqTime() const { return _req_time; }
  const std::shared_ptr<std::string> getError() const { return _err; }
  std::vector<std::shared_ptr<CmdItem>> &getAllCmds() { return _reqCmds; }
  void appendReqPayload(std::string &&one_req_payload) {
    _req_all_payloads += one_req_payload;
  }
  void setRespTime(timeval t) { _resp_time = t; }
  timeval getRespTime() const { return _resp_time; }

  void setRespPayload(std::string &&one_resp_payload) {
    _resp_one_payload = one_resp_payload;
  }
  const std::string &getRespPayload() const { return _resp_one_payload; }

  std::string simpleDecodeResp();

  int run();

 private:
  std::string _src_ip;
  int _src_port;
  std::string _dst_ip;
  int _dst_port;
  std::string _req_all_payloads;
  std::string _resp_one_payload;
  timeval _req_time;
  timeval _resp_time;
  double _cost_time_ms;  // cost time in ms
  std::shared_ptr<std::string> _err;

  std::vector<std::shared_ptr<CmdItem>> _reqCmds;
};

#endif  // MYREDISCAPTURER_CAPTURE_DECODER_H_