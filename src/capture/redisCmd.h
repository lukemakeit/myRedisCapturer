// Copyright [2022] <Copyright lukexwang@tencent.com>

#ifndef MYREDISCAPTURER_CAPTURE_REDISCMD_H_
#define MYREDISCAPTURER_CAPTURE_REDISCMD_H_

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "decoder.h"

#define ADMIN_FLAG "admin"
#define WRITE_FLAG "write"
#define READONLY_FLAG "read-only"

struct RedisCmdMeta {
  std::string _name;
  int _arity;
  std::string _sflags;
  int _firstKey;
  int _lastKey;
  int _keyStep;

  bool preCheck(CmdItem &cmd);

  std::shared_ptr<std::string> GetKeysAndCntAndMaxKey(
      std::shared_ptr<CmdItem> cmd);

  std::shared_ptr<std::string> MaxValueAndValueCnt(
      std::shared_ptr<CmdItem> cmd);
};

inline std::once_flag cmdTableFlag;
inline std::shared_ptr<std::unordered_map<std::string, RedisCmdMeta>>
    RedisCommandTable;

void initRedisCommandTable();
const std::shared_ptr<std::unordered_map<std::string, RedisCmdMeta>>
GetRedisCommandTable();
#endif  // MYREDISCAPTURER_CAPTURE_REDISCMD_H_