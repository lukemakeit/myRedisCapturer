// Copyright [2022] <Copyright lukexwang@tencent.com>

#include "decoder.h"

#include "glog/logging.h"
#include "redisCmd.h"
#include "util.h"

int RedisAofDecoder::run() {
  std::istringstream ss(_payload);
  std::string line;
  std::shared_ptr<CmdItem> cmditem = std::make_shared<CmdItem>();
  try {
    while (std::getline(ss, line)) {
      if (line.at(0) == '*') {
        cmditem->multiCnt = std::stoi(line.substr(1, line.size() - 1));
      } else {
        // fist char not '*',format not correct
        continue;
      }
      for (int i = 0; i < cmditem->multiCnt; i++) {
        if (std::getline(ss, line)) {
          if (line.at(0) != '$') {
            LOG(WARNING) << "format not correct,line not start with $, line:"
                         << line;
            break;
          }
          cmditem->bulkLen = std::stoi(line.substr(1, line.size() - 1));
          if (cmditem->bulkLen > cmditem->maxArgvSize) {
            cmditem->maxArgvSize = cmditem->bulkLen;
          }
          if (!ss.tellg()) break;
          auto availLen = _payload.size() - ss.tellg();
          auto tmpBufSize = cmditem->bulkLen + 2;
          if (tmpBufSize > availLen) {
            LOG(WARNING) << string_format(
                "format not correct,partitial commands,expect %d "
                "bytes,now available %d bytes",
                tmpBufSize, availLen);
            tmpBufSize = availLen;
          }
          std::vector<char> tmpVec(tmpBufSize, 0);
          ss.readsome(&tmpVec.front(), tmpBufSize);
          // if ((tmpBuff[cmditem->bulkLen] != '\r' ||
          //      tmpBuff[cmditem->bulkLen + 1] != '\n') &&
          //     (ss.eof() || ss.fail())) {
          //   LOG(WARNING) << string_format(
          //       "format not correct,partitial commands,expect %d "
          //       "bytes,now read %d bytes",
          //       cmditem->bulkLen + 2, strlen(tmpBuff));
          //   break;
          // }
          std::string item =
              redisNoRawStr(&tmpVec.front(), tmpBufSize < cmditem->bulkLen + 2
                                                 ? tmpBufSize
                                                 : cmditem->bulkLen);
          cmditem->cmdArgs.emplace_back(std::move(item));
          if (tmpBufSize < cmditem->bulkLen + 2) {
            break;
          }
        }
      }
      if (cmditem->cmdArgs.size() != cmditem->multiCnt &&
          cmditem->cmdArgs.size() <= 1) {
        LOG(WARNING) << "partitial commands:"
                     << stringsJoin(cmditem->cmdArgs, " ").c_str();
        continue;
      }
      std::string cmdName = cmditem->cmdArgs.at(0);
      trimChar(cmdName, '"');
      std::transform(cmdName.begin(), cmdName.end(), cmdName.begin(),
                     [](unsigned char c) { return std::tolower(c); });

      auto cmdTable = GetRedisCommandTable();
      auto cmdMeta = cmdTable->find(cmdName);
      if (cmdMeta == cmdTable->end()) {
        // not found command
        LOG(WARNING) << "not found command:" << cmdName;
        return -1;
      }
      auto err = cmdMeta->second.GetKeysAndCntAndMaxKey(cmditem);
      if (err != nullptr) {
        LOG(WARNING) << *err;
        return -1;
      }
      err = cmdMeta->second.MaxValueAndValueCnt(cmditem);
      if (err != nullptr) {
        LOG(WARNING) << *err;
        return -1;
      }
      _reqCmds.push_back(cmditem);
      cmditem = std::make_shared<CmdItem>();
    }
  } catch (const std::string& ex) {
    LOG(WARNING) << ex;
  } catch (const std::runtime_error& re) {
    LOG(WARNING) << re.what();
  } catch (const std::exception& ex) {
    LOG(WARNING) << ex.what();
  } catch (...) {
    std::exception_ptr p = std::current_exception();
    LOG(WARNING) << "Unknown failure occurred."
                 << (p ? p.__cxa_exception_type()->name() : "null");
  }
}