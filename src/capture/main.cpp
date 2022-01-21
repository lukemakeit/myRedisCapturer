#include <signal.h>

#include "capture.h"
#include "cmdline.h"
#include "glog/logging.h"
#include "util.h"

int32_t main(int32_t argc, char* argv[]) {
  cmdline::parser cmd;
  try {
    cmd.add<std::string>("device", 'd', "required,network device. e.g. eth1",
                         true, "");
    cmd.add<std::string>("port", 'p',
                         "required,redis (dst) port(s). e.g. default 6379",
                         true, "");
    cmd.add<std::string>("ip", 'i', "required,redis (dst) ip", true, "");
    cmd.add<int32_t>("timeout", 't',
                     "duration of capture in seconds. (0 means no limit)", true,
                     0);
    cmd.add<std::string>("output-file", 'f', "store output into file path..",
                         false, "");
    cmd.add<std::string>("log-file", 'e',
                         "store log info into file path.default ./capture.log",
                         false, "./capture.log");
    cmd.add<int32_t>("threads", 'n',
                     "Number of threads parsing packets,default 4", false, 4);
    cmd.add<int32_t>(
        "only-big-req", '\0',
        "default 0 means no limit.Only output requests that process "
        "multibulklen > {--only-big-req}, such as mset or mget or pipeline",
        false, 0);
    cmd.add<int32_t>("only-big-val", '\0',
                     "default 0 means no limit.only output write requests with "
                     "a large value",
                     false, 0);
    cmd.add("version", 'v', "show version info");
    cmd.set_version(
        "myRedisCapturer v1.0.0, by lukexwang@tencent.com. 2022-01-18");
    cmd.parse_check(argc, argv);
  } catch (cmdline::cmdline_error& e) {
    LOG(ERROR) << e.what();
    return -1;
  }

  std::string dev = cmd.get<std::string>("device");
  std::string port = cmd.get<std::string>("port");
  std::string ip_str = cmd.get<std::string>("ip");
  int32_t duration = cmd.get<int32_t>("timeout");  // seconds
  std::string output_file = cmd.get<std::string>("output-file");
  std::string log_file = cmd.get<std::string>("log-file");
  int32_t threads = cmd.get<int32_t>("threads");
  int32_t onlyBigReq = cmd.get<int32_t>("only-big-req");
  int32_t onlyBigVal = cmd.get<int32_t>("only-big-val");

  // glog config set
  FLAGS_logtostderr = false;
  FLAGS_alsologtostderr = false;
  google::SetLogDestination(google::INFO, log_file.c_str());
  google::SetLogDestination(google::WARNING, log_file.c_str());
  google::SetLogDestination(google::ERROR, log_file.c_str());
  google::SetLogDestination(google::FATAL, log_file.c_str());
  google::SetLogSymlink(google::INFO, "");
  google::SetLogSymlink(google::WARNING, "");
  google::SetLogSymlink(google::ERROR, "");
  google::SetLogSymlink(google::FATAL, "");
  FLAGS_timestamp_in_logfile_name = false;
  google::InitGoogleLogging(argv[0]);

  Capture task;
  task.setDevice(dev)
      .setIP(ip_str)
      .setPort(port)
      .setTimeout(duration)
      .setOutputFile(output_file)
      .setThreads(threads)
      .setOnlyBigReq(onlyBigReq)
      .setOnlyBigVal(onlyBigVal);
  if (task.getError()) {
    return -1;
  }
  task.run();

  return 0;
}