#include "capture.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <ctime>
#include <functional>
#include <string>
#include <thread>

#include "cmdline.h"
#include "glog/logging.h"

void signalHandler(int signum) {
  g_quit.store(true);
  shutdown_handler(signum);
}

Capture& Capture::setDevice(const std::string& device) {
  if (_err) {
    return *this;
  }
  if (device.empty()) {
    _err = std::make_shared<std::string>(
        string_format("device:%s cannot be empty", device.c_str()));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _device = device;
  return *this;
}

Capture& Capture::setIP(const std::string& ip) {
  if (_err) {
    return *this;
  }
  if (ip.empty()) {
    _err = std::make_shared<std::string>(
        string_format("ip:%s cannot be empty", ip.c_str()));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _ip = ip;
  return *this;
}

Capture& Capture::setPort(const std::string& port) {
  if (_err) {
    return *this;
  }
  // if (port <= 0 || port > 65535) {
  //   _err = std::make_shared<std::string>(
  //       string_format("port:%d is invalid, 0<port<65535 is required", port));
  //   return *this;
  // }
  if (port.empty()) {
    _err = std::make_shared<std::string>(
        string_format("port:%s cannot be empty", port.c_str()));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _port = port;
  return *this;
}

Capture& Capture::setTimeout(const int32_t timeout) {
  if (_err) {
    return *this;
  }
  if (timeout < 0) {
    _err = std::make_shared<std::string>(
        string_format("timeout:%d <0 is invalid", timeout));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _timeout = timeout;
  return *this;
}

Capture& Capture::setOnlyBigReq(const int32_t onlyBigRq) {
  if (_err) {
    return *this;
  }
  if (onlyBigRq < 0) {
    _err = std::make_shared<std::string>(
        string_format("--only-big-req:%d <0 is invalid", onlyBigRq));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _only_big_req = onlyBigRq;
  return *this;
}

Capture& Capture::setOnlyBigVal(const int32_t onlyBigVal) {
  if (_err) {
    return *this;
  }
  if (onlyBigVal < 0) {
    _err = std::make_shared<std::string>(
        string_format("--only-big-val:%d <0 is invalid", onlyBigVal));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _only_big_val = onlyBigVal;
  return *this;
}

Capture& Capture::setOutputFile(const std::string& outputFile) {
  if (_err) {
    return *this;
  }
  if (!outputFile.empty()) {
    _out_of.open(outputFile);
    _out_os.rdbuf(_out_of.rdbuf());
  }
  _output_file = outputFile;
  return *this;
}
Capture& Capture::setThreads(const int32_t threads) {
  if (_err) {
    return *this;
  }
  if (threads < 1) {
    _err = std::make_shared<std::string>(
        string_format("threads:%d <1 is invalid", threads));
    LOG(ERROR) << _err->c_str();
    return *this;
  }
  _threads = threads;
  return *this;
}

bool Capture::isAvailable() {
  if (_device.empty()) {
    return false;
  }
  if (_port.empty()) {
    return false;
  }
  if (_timeout < 0 || _output_file.empty()) {
    return false;
  }
  return true;
}

std::string Capture::getFilter() {
  const int32_t filter_buf_size = 1024;
  char port_filter_buf[filter_buf_size] = {0};
  std::string host_filter;
  if (_port.find(',') != std::string::npos) {
    // port contains ',': multi port "30000,30002"
    std::string tmp(_port);
    size_t pos = 0;
    while ((pos = tmp.find(",", pos)) != std::string::npos) {
      tmp.replace(pos, 1, " or ");
    }

    snprintf(port_filter_buf, filter_buf_size, "tcp dst port (%s)",
             tmp.c_str());
  } else if (_port.find('-') != std::string::npos) {
    // port contains '-': portrange "30000-30009"
    snprintf(port_filter_buf, filter_buf_size, "tcp dst portrange %s",
             _port.c_str());
  } else {
    // one port "30000"
    snprintf(port_filter_buf, filter_buf_size, "tcp dst port %s",
             _port.c_str());
  }

  if (!_ip.empty()) {
    host_filter = " and dst host " + _ip;
  }
  return port_filter_buf + host_filter;
}

void Capture::run() {
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* handle = NULL;
  bpf_u_int32 mask = 0;
  bpf_u_int32 net = 0;
  if (pcap_lookupnet(_device.c_str(), &net, &mask, errbuf) == -1) {
    _err = std::make_shared<std::string>(string_format(
        "[ERR] can't get netmask for device %s", _device.c_str()));
    LOG(ERROR) << _err->c_str();
    return;
  }
  handle = pcap_open_live(_device.c_str(), 65535, 1, 1000, errbuf);
  if (handle == NULL) {
    _err = std::make_shared<std::string>(string_format(
        "[ERR] Couldn't open device %s,err:%s", _device.c_str(), errbuf));
    LOG(ERROR) << _err->c_str();
    return;
  }

  std::string filter = getFilter();
  if (_err) {
    return;
  }
  LOG(INFO) << "filter: " << filter << std::endl;
  struct bpf_program fp;
  if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
    _err = std::make_shared<std::string>(
        string_format("[ERR] can not parse dev %s, port %s,err:%s",
                      _device.c_str(), _port.c_str(), pcap_geterr(handle)));
    LOG(ERROR) << _err->c_str();
    return;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    _err = std::make_shared<std::string>(
        string_format("[ERR] can not install filter dev %s, port %s,err:%s",
                      _device.c_str(), _port.c_str(), pcap_geterr(handle)));
    LOG(ERROR) << *_err;
    return;
  }

  shutdown_handler = [&](int signum) {
    if (signum == SIGALRM) {
      LOG(INFO) << "SIGALRM trigger";
    } else if (signum == SIGINT) {
      LOG(INFO) << "SIGINT trigger";
    }
    pcap_breakloop(handle);
  };
  alarm(_timeout);
  // register handler for timeout
  signal(SIGALRM, signalHandler);
  // register handler for sigint (ctrl + c)
  signal(SIGINT, signalHandler);

  this->parallelConsumTasks(_threads);

  pcap_loop(handle, 0, my_packet_handler, reinterpret_cast<u_char*>(this));

  struct pcap_stat ps;
  pcap_stats(handle, &ps);
  LOG(INFO) << string_format(
      "packet loss: %3.6f%% total captured packets: %d\n",
      (double)(100 * ps.ps_drop) / ps.ps_recv, _packet_count_ac.load());
  pcap_close(handle);

  // additional 2 threads shorten consumption time
  this->parallelConsumTasks(2);
  this->waitConsumers();
}

void Capture::pushTask(std::shared_ptr<RedisAofDecoder> task) {
  {
    std::lock_guard<std::mutex> lk(_decoder_mut);
    _decoder_queue.push(task);
  }
  _decoder_cond.notify_one();
}

void Capture::consumerTask() {
  for (;;) {
    std::shared_ptr<RedisAofDecoder> taskPtr(nullptr);
    {
      std::unique_lock<std::mutex> uk(_decoder_mut);
      _decoder_cond.wait(
          uk, [&]() { return _is_shutdown.load() || !_decoder_queue.empty(); });
      if (_is_shutdown.load() && _decoder_queue.empty()) {
        break;
      }
      if (!_decoder_queue.empty()) {
        taskPtr = _decoder_queue.front();
        _decoder_queue.pop();
      }
      // lock release
    }
    if (taskPtr) {
      taskPtr->run();
      this->outputCmds(taskPtr);
    }
  }
  LOG(INFO) << "thread id:" << std::this_thread::get_id() << " end";
}
void Capture::parallelConsumTasks(int32_t threadCnt) {
  for (int32_t i = 0; i < threadCnt; i++) {
    _threeads_list.push_back(std::thread(&Capture::consumerTask, this));
  }
}
void Capture::waitConsumers() {
  _is_shutdown.store(true);
  _decoder_cond.notify_all();
  for (auto& ele : _threeads_list) {
    if (ele.joinable()) {
      ele.join();
    }
  }
}
void Capture::outputCmds(std::shared_ptr<RedisAofDecoder> taskPtr) {
  if (taskPtr->getAllCmds().empty()) {
    return;
  }
  std::size_t cmdCount = taskPtr->getAllCmds().size();
  std::vector<std::string> prefixList;
  if (cmdCount == 1) {
    prefixList.emplace_back("[NORMAL]");
  } else {
    char tmpStr[64] = {0};
    for (std::size_t idx = 0; idx < cmdCount; idx++) {
      snprintf(tmpStr, 64, "[PIPELINE-%d-%d]", idx + 1, cmdCount);
      prefixList.emplace_back(tmpStr, strlen(tmpStr));
    }
  }
  time_t reqTime = taskPtr->getReqTime();
  std::tm* ptm = std::localtime(&reqTime);
  char timeFormat[32] = {0};
  std::strftime(timeFormat, 32, "%Y-%m-%d %H:%M:%S", ptm);

  std::vector<std::shared_ptr<CmdItem>>& srcCmds = taskPtr->getAllCmds();
  std::vector<std::shared_ptr<CmdItem>> keepCmds;
  if (_only_big_req == 0 && _only_big_val == 0) {
    std::copy(srcCmds.begin(), srcCmds.end(), std::back_inserter(keepCmds));
  } else if (_only_big_req > 0) {
    if (srcCmds.size() > _only_big_req) {
      // big pipeline
      std::copy(srcCmds.begin(), srcCmds.end(), std::back_inserter(keepCmds));
    } else {
      for (auto& ele : srcCmds) {
        if (ele->multiCnt > _only_big_req) {
          // so much keys or values
          keepCmds.push_back(ele);
        }
      }
    }
  } else if (_only_big_val > 0) {
    for (auto& ele : srcCmds) {
      if (ele->maxArgvSize > _only_big_val) {
        keepCmds.push_back(ele);
      }
    }
  }

  std::lock_guard<std::mutex> lk(_out_mut);
  std::size_t idx = 0;
  for (auto& ele : keepCmds) {
    _out_os << string_format(
        "[%s] client: %s:%d => %s:%d %s multiBulkLen: %d "
        "maxArgvSize: %d %s\n",
        timeFormat, taskPtr->getSrcIP().c_str(), taskPtr->getSrcPort(),
        taskPtr->getDstIP().c_str(), taskPtr->getDstPort(),
        prefixList.at(idx).c_str(), ele->multiCnt, ele->maxArgvSize,
        stringsJoin(ele->cmdArgs, " ").c_str());
    idx++;
  }
}

/*
 * http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/
 * https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void my_packet_handler(u_char* args, const struct pcap_pkthdr* pkthdr,
                       const u_char* packet) {
  if (args == NULL) {
    return;
  }
  Capture* cap = reinterpret_cast<Capture*>(args);
  cap->_packet_count_ac.fetch_add(1);
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  unsigned short ipHeaderLen;
  const struct tcphdr* tcpHeader;
  int totalHeadersSize;
  char sourceIp[INET_ADDRSTRLEN];
  char destIp[INET_ADDRSTRLEN];
  u_int sourcePort, destPort;
  u_char* payload;
  int payloadLength = 0;
  std::string dataStr = "";

  ethernetHeader = (struct ether_header*)packet;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

    if (ipHeader->ip_p == IPPROTO_TCP) {
      ipHeaderLen = sizeof(struct ip);
      tcpHeader =
          (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      sourcePort = ntohs(tcpHeader->source);
      destPort = ntohs(tcpHeader->dest);
      totalHeadersSize =
          sizeof(struct ether_header) + ipHeaderLen + tcpHeader->doff * 4;

      payloadLength = pkthdr->caplen - totalHeadersSize;
      payload = (u_char*)(packet + totalHeadersSize);
      if (payloadLength > 0) {
        auto decoderTask = std::make_shared<RedisAofDecoder>(
            std::string(sourceIp), int(sourcePort), std::string(destIp),
            int(destPort), std::string((char*)payload, payloadLength),
            pkthdr->ts.tv_sec);
        cap->pushTask(decoderTask);
      }
    }
  }
}