#ifndef _MY_REDIS_CAPTURE_CAPTURE_H
#define _MY_REDIS_CAPTURE_CAPTURE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "decoder.h"
#include "util.h"

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header,
                       const u_char* packet);
void my_packet_handler02(u_char* args, const struct pcap_pkthdr* header,
                         const u_char* packet);
inline std::atomic<bool> g_quit(false);

inline std::function<void(int)> shutdown_handler;
void signalHandler(int signum);

class Capture {
  using captureClock = std::chrono::high_resolution_clock;
  using captureSecond = std::chrono::duration<int, std::ratio<1>>;
  friend void my_packet_handler(u_char* args, const struct pcap_pkthdr* pkthdr,
                                const u_char* packet);

 public:
  Capture()
      : _is_available(false),
        _is_shutdown(false),
        _out_os(std::cout.rdbuf()),
        _err(nullptr) {}
  Capture& setDevice(const std::string& device);
  Capture& setIP(const std::string& ip);
  Capture& setPort(const std::string& port);
  Capture& setTimeout(const int32_t timeout);
  Capture& setOnlyBigReq(const int32_t onlyBigRq);
  Capture& setOnlyBigVal(const int32_t onlyBigVal);
  Capture& setThreads(const int32_t threads);
  Capture& setOutputFile(const std::string& outputFile);
  const std::string& getDevice() const { return _device; }
  const std::string& getPort() const { return _port; }
  const std::string& getIP() const { return _ip; }
  int getTimeout() const { return _timeout; }
  int32_t getOnlyBigReq() const { return _only_big_req; }
  int32_t getOnlyBigVal() const { return _only_big_val; }
  const std::string& getOutputFile() const { return _output_file; }
  const std::shared_ptr<std::string> getError() const { return _err; }

  bool isAvailable();
  void run();

 private:
  std::string getFilter();
  void pushTask(std::shared_ptr<RedisAofDecoder> task);
  void consumerTask();
  void parallelConsumTasks(int32_t);
  void waitConsumers();
  void outputCmds(std::shared_ptr<RedisAofDecoder> taskPtr);
  bool checkTimeout(std::chrono::time_point<captureClock> begin) {
    int useSec =
        std::chrono::duration_cast<captureSecond>(captureClock::now() - begin)
            .count();
    return useSec > _timeout;
  }

 private:
  std::string _device;
  std::string _port;
  std::string _ip;
  int32_t _timeout;
  std::string _output_file;
  int32_t _threads;
  bool _is_available;

  std::atomic<bool> _is_shutdown;
  std::mutex _decoder_mut;
  std::condition_variable _decoder_cond;
  std::queue<std::shared_ptr<RedisAofDecoder>> _decoder_queue;
  std::vector<std::thread> _threeads_list;

  std::ofstream _out_of;
  std::ostream _out_os;
  std::mutex _out_mut;

  int32_t _only_big_req;
  int32_t _only_big_val;
  std::atomic<int> _packet_count_ac;

  std::shared_ptr<std::string> _err;
};

#endif