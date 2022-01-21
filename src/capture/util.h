#ifndef _MY_REDIS_CAPTURE_UTIL_H
#define _MY_REDIS_CAPTURE_UTIL_H
#include <ctype.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

static void ltrimSpace(std::string &s);

static void rtrimSpace(std::string &s);

static inline void trimSpace(std::string &s);

void ltrimChar(std::string &s, const char &c);

void rtrimChar(std::string &s, const char &c);

void trimChar(std::string &s, const char &c);

std::vector<std::string> stringSplit(const std::string &s, char ch);

template <typename T>
std::string stringsJoin(T &strArr, const std::string &seq) {
  if (strArr.size() == 0) {
    return "";
  }
  return std::accumulate(strArr.cbegin(), strArr.cend(), std::string(),
                         [&](std::string &ss, const std::string &s) {
                           return ss.empty() ? s : ss + seq + s;
                         });
}

template <typename... Args>
std::string string_format(const std::string &format, Args... args) {
  // Extra space for '\0'
  int size_s = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
  if (size_s <= 0) {
    throw std::runtime_error("Error during formatting.");
  }
  auto size = static_cast<size_t>(size_s);
  auto buf = std::make_unique<char[]>(size);
  std::snprintf(buf.get(), size, format.c_str(), args...);
  // We don't want the '\0' inside
  return std::string(buf.get(), buf.get() + size - 1);
}

/*
 * Refer to the implementation of sdscatrepr() in redis
 */
std::string redisNoRawStr(const char *p, size_t len);
#endif