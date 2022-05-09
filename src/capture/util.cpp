#include "util.h"

static void ltrimSpace(std::string &s) {
  s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), [](unsigned char ch) {
            return std::isspace(ch);
          }));
}

static void rtrimSpace(std::string &s) {
  s.erase(std::find_if_not(s.rbegin(), s.rend(),
                           [](unsigned char ch) { return std::isspace(ch); })
              .base(),
          s.end());
}

static inline void trimSpace(std::string &s) {
  ltrimSpace(s);
  rtrimSpace(s);
}

void ltrimChar(std::string &s, const char &c) {
  s.erase(s.begin(),
          std::find_if_not(s.begin(), s.end(),
                           [&](unsigned char ch) { return ch == c; }));
}

void rtrimChar(std::string &s, const char &c) {
  s.erase(std::find_if_not(s.rbegin(), s.rend(),
                           [&](unsigned char ch) { return ch == c; })
              .base(),
          s.end());
}

void trimChar(std::string &s, const char &c) {
  ltrimChar(s, c);
  rtrimChar(s, c);
}

std::vector<std::string> stringSplit(const std::string &s, const char ch) {
  std::vector<std::string> ret;
  std::stringstream ss(s);
  std::string segment;
  while (std::getline(ss, segment, ch)) {
    ret.push_back(segment);
  }
  return ret;
}
/*
 * Refer to the implementation of sdscatrepr() in redis
 */
std::string redisNoRawStr(const char *p, size_t len) {
  std::stringstream ss;
  const int bufSize = 20;
  char buf[bufSize];
  ss << "\"";
  while (len--) {
    switch (*p) {
      case '\\':
      case '"':
        snprintf(buf, bufSize, "\\%c", *p);
        ss << buf;
        break;
      case '\n':
        ss << "\\n";
        break;
      case '\r':
        ss << "\\r";
        break;
      case '\t':
        ss << "\\t";
        break;
      case '\a':
        ss << "\\a";
        break;
      case '\b':
        ss << "\\b";
        break;
      default:
        if (isprint(*p))
          snprintf(buf, bufSize, "%c", *p);
        else
          snprintf(buf, bufSize, "\\x%02x", (unsigned char)*p);
        ss << buf;
        break;
    }
    p++;
  }
  ss << "\"";
  return ss.str();
}