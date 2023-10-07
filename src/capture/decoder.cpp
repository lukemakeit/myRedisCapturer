// Copyright [2022] <Copyright lukexwang@tencent.com>

#include "decoder.h"

#include "glog/logging.h"
#include "redisCmd.h"
#include "util.h"

int RedisAofDecoder::run() {
  std::istringstream ss(_req_all_payloads);
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
          auto availLen = _req_all_payloads.size() - ss.tellg();
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
        // unknown command
        LOG(WARNING) << "unknown command:" << cmdName;
        // LOG(ERROR) << "unknown command:" << stringsJoin(cmditem->cmdArgs, "
        // ");
        cmditem->unknown_cmd = true;
        // return -1;
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

// 简单解析 redis resp包内容,并返回简单字符串
// 1. 如果resp package以+打头,代表 simple strings, return
// "resp_size:$package_size"
// 2. 如果resp package以-打头,代表 simple errors, return
// "resp_error:$package_data"
// 3. 如果resp package以:打头,代表 integers, return "resp_size:$package_size"
// 4. 如果resp package以$打头,代表 bulk
// strings,解析出$<length>\r\n<data>\r\n中<length>, return "resp_size:$length"
// 5. 如果resp package以*打头,代表
// arrays,解析出*<number-of-elements>\r\n<element-1>...<element-n>中<number-for-elements>,
// return "resp_eles_count:$number-for-elements"
// 6. 如果resp package以_打头,代表 nulls, return "resp_size:$package_data"
// 7. 如果resp package以#打头,代表 booleans, return "resp_size:$package_size"
// 8. 如果resp package以,打头,代表 doubles, return "resp_size:$package_size"
// 9. 如果resp package以(打头,代表 big numbers, return "resp_size:$package_size"
// 10. 如果resp package以!打头,代表 bulk errors, return
// "resp_error:$package_data"
// 11. 如果resp package以=打头,代表 verbatim
// strings,解析出=<length>\r\n<encoding>:<data>\r\n中<length>大小, return
// "resp_size:$length"
// 12. 如果resp package以%打头,代表
// maps,解析出%<number-of-entries>\r\n<key-1><value-1>...<key-n><value-n>中<number-of-entries>,
// return "resp_entries_cnt:$number-of-entries"
// 13. 如果resp package以~打头,代表
// sets,解析出~<number-of-elements>\r\n<element-1>...<element-n>中<number-of-elements>,
// return "resp_eles_count:$number-of-elements"
// 14. 如果resp package以>打头,代表
// pushs,解析出><number-of-elements>\r\n<element-1>...<element-n>中<number-of-elements>大小,
// return "resp_eles_count:$number-of-elements"
// 15. 否则返回 "unknown resp format"
std::string RedisAofDecoder::simpleDecodeResp() {
  std::string resp = _resp_one_payload;
  if (resp.empty()) {
    return "resp_size:0";
  }
  std::string respType = resp.substr(0, 1);
  std::string respData = resp.substr(1);
  if (respType == "+") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == "-") {
    // respData 删除结尾最后的\r\n
    respData.erase(respData.size() - 2);
    return string_format("resp_error: %s", respData.c_str());
  } else if (respType == ":") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == "$") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respSize = respData.substr(0, pos);
    return string_format("resp_size: %s", respSize.c_str());
  } else if (respType == "*") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respElesCnt = respData.substr(0, pos);
    return string_format("resp_eles_count: %s", respElesCnt.c_str());
  } else if (respType == "_") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == "#") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == ",") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == "(") {
    return string_format("resp_size: %d", respData.size());
  } else if (respType == "!") {
    // respData 删除结尾最后的\r\n
    respData.erase(respData.size() - 2);
    return string_format("resp_error: %s", respData.c_str());
  } else if (respType == "=") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respSize = respData.substr(0, pos);
    return string_format("resp_size: %s", respSize.c_str());
  } else if (respType == "%") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respEntriesCnt = respData.substr(0, pos);
    return string_format("resp_entries_cnt: %s", respEntriesCnt.c_str());
  } else if (respType == "~") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respElesCnt = respData.substr(0, pos);
    return string_format("resp_eles_count: %s", respElesCnt.c_str());
  } else if (respType == ">") {
    std::string::size_type pos = respData.find("\r\n");
    if (pos == std::string::npos) {
      return "unknown resp format";
    }
    std::string respElesCnt = respData.substr(0, pos);
    return string_format("resp_eles_count: %s", respElesCnt.c_str());
  } else {
    return "unknown resp format";
  }
}