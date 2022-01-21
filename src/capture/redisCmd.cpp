#include "redisCmd.h"

#include "glog/logging.h"
#include "util.h"

std::shared_ptr<std::string> RedisCmdMeta::GetKeysAndCntAndMaxKey(
    std::shared_ptr<CmdItem> cmd) {
  if (_sflags.find(ADMIN_FLAG) != std::string::npos) {
    return nullptr;
  }
  if (_firstKey == 0) {
    return nullptr;
  }
  try {
    int last = _lastKey;
    if (last < 0) {
      last = last + cmd->cmdArgs.size();
    }
    long maxLen = 0;
    for (int i = _firstKey; i <= last; i += _keyStep) {
      if (cmd->cmdArgs.at(i).size() > maxLen) {
        cmd->maxKey = cmd->cmdArgs.at(i);
        maxLen = cmd->cmdArgs.at(i).size();
      }
      cmd->cmdKeys.push_back(cmd->cmdArgs.at(i));
      cmd->keyCnt++;
    }
  } catch (const std::string &ex) {
    LOG(WARNING) << ex << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(ex);
  } catch (const std::runtime_error &re) {
    LOG(WARNING) << re.what() << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(re.what());
  } catch (const std::exception &ex) {
    LOG(WARNING) << ex.what() << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(ex.what());
  } catch (...) {
    std::exception_ptr p = std::current_exception();
    LOG(WARNING) << "Unknown failure occurred."
                 << (p ? p.__cxa_exception_type()->name() : "null")
                 << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>("Unknown failure occurred.");
  }
  return nullptr;
}

/*
Only handle write commands
1. The admin/read command has no value, only the write command is processed;
2. If firstKey == lastKey, the command has only one key. Then firstKey is
followed by value. Count "ex" "60" "nx" in "set a 1 ex 60 nx" as 3 values;
3. If firstKey != lastKey, then the value after the key is value. For example,
MSET key1 Hello key2 World, then Hello and World are two values;
*/
std::shared_ptr<std::string> RedisCmdMeta::MaxValueAndValueCnt(
    std::shared_ptr<CmdItem> cmd) {
  if (_sflags.find(READONLY_FLAG) != std::string::npos) {
    return nullptr;
  }
  if (_sflags.find(ADMIN_FLAG) != std::string::npos) {
    return nullptr;
  }
  if (_firstKey == 0) {
    return nullptr;
  }
  long maxLen = 0;
  int last = _lastKey;
  if (last < 0) {
    last = last + cmd->cmdArgs.size();
  }

  try {
    if (_firstKey == _lastKey) {
      auto begin = cmd->cmdArgs.begin() + _firstKey + 1;
      for (; begin != cmd->cmdArgs.end(); begin++) {
        cmd->ValCnt++;
        if (begin->size() > maxLen) {
          cmd->maxVal = *begin;
          maxLen = begin->size();
        }
      }
    } else {
      int start = _firstKey;
      int end = start + _keyStep;
      while (end <= last) {
        // args between two keys are values
        for (int j = start + 1; j < end; j++) {
          cmd->ValCnt++;
          if (cmd->cmdArgs.at(j).size() > maxLen) {
            cmd->maxVal = cmd->cmdArgs.at(j);
            maxLen = cmd->cmdArgs.at(j).size();
          }
        }
        start = end;
        end = start + _keyStep;
      }
      // parts after lastKey are values
      start = last;
      end = cmd->cmdArgs.size();
      for (int j = start + 1; j < end; j++) {
        cmd->ValCnt++;
        if (cmd->cmdArgs.at(j).size() > maxLen) {
          cmd->maxVal = cmd->cmdArgs.at(j);
          maxLen = cmd->cmdArgs.at(j).size();
        }
      }
    }
  } catch (const std::string &ex) {
    LOG(ERROR) << ex << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(ex);
  } catch (const std::runtime_error &re) {
    LOG(ERROR) << re.what() << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(re.what());
  } catch (const std::exception &ex) {
    LOG(ERROR) << ex.what() << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>(ex.what());
  } catch (...) {
    std::exception_ptr p = std::current_exception();
    LOG(ERROR) << "Unknown failure occurred."
               << (p ? p.__cxa_exception_type()->name() : "null")
               << " command:" << stringsJoin(cmd->cmdArgs, " ");
    return std::make_shared<std::string>("Unknown failure occurred.");
  }

  return nullptr;
}

const std::shared_ptr<std::unordered_map<std::string, RedisCmdMeta>>
GetRedisCommandTable() {
  std::call_once(cmdTableFlag, initRedisCommandTable);
  return RedisCommandTable;
}

void initRedisCommandTable() {
  RedisCommandTable =
      std::make_shared<std::unordered_map<std::string, RedisCmdMeta>>();
  RedisCommandTable->insert({"module", {"module", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"get", {"get", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"getex", {"getex", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"getdel", {"getdel", 2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"set", {"set", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"setnx", {"setnx", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"setex", {"setex", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"psetex", {"psetex", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"append", {"append", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"strlen", {"strlen", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"del", {"del", -2, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"unlink", {"unlink", -2, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"exists", {"exists", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"setbit", {"setbit", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"getbit", {"getbit", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"bitfield", {"bitfield", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"bitfield_ro", {"bitfield_ro", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"setrange", {"setrange", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"getrange", {"getrange", 4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"substr", {"substr", 4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"incr", {"incr", 2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"decr", {"decr", 2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"mget", {"mget", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"rpush", {"rpush", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lpush", {"lpush", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"rpushx", {"rpushx", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lpushx", {"lpushx", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"linsert", {"linsert", 5, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"rpop", {"rpop", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lpop", {"lpop", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"brpop", {"brpop", -3, WRITE_FLAG, 1, -2, 1}});
  RedisCommandTable->insert(
      {"brpoplpush", {"brpoplpush", 4, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"blmove", {"blmove", 6, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"blpop", {"blpop", -3, WRITE_FLAG, 1, -2, 1}});
  RedisCommandTable->insert({"llen", {"llen", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lindex", {"lindex", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lset", {"lset", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lrange", {"lrange", 4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"ltrim", {"ltrim", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lpos", {"lpos", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"lrem", {"lrem", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"rpoplpush", {"rpoplpush", 3, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"lmove", {"lmove", 5, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"sadd", {"sadd", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"srem", {"srem", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"smove", {"smove", 4, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert(
      {"sismember", {"sismember", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"smismember", {"smismember", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"scard", {"scard", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"spop", {"spop", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"srandmember", {"srandmember", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"sinter", {"sinter", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"sinterstore", {"sinterstore", -3, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"sunion", {"sunion", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"sunionstore", {"sunionstore", -3, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"sdiff", {"sdiff", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"sdiffstore", {"sdiffstore", -3, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert(
      {"smembers", {"smembers", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"sscan", {"sscan", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zadd", {"zadd", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zincrby", {"zincrby", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zrem", {"zrem", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zremrangebyscore", {"zremrangebyscore", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zremrangebyrank", {"zremrangebyrank", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zremrangebylex", {"zremrangebylex", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zunionstore", {"zunionstore", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zinterstore", {"zinterstore", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zdiffstore", {"zdiffstore", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zunion", {"zunion", -3, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"zinter", {"zinter", -3, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"zdiff", {"zdiff", -3, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"zrange", {"zrange", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrangestore", {"zrangestore", -5, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert(
      {"zrangebyscore", {"zrangebyscore", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrevrangebyscore", {"zrevrangebyscore", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrangebylex", {"zrangebylex", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrevrangebylex", {"zrevrangebylex", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zcount", {"zcount", 4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zlexcount", {"zlexcount", 4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrevrange", {"zrevrange", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zcard", {"zcard", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zscore", {"zscore", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zmscore", {"zmscore", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zrank", {"zrank", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"zrevrank", {"zrevrank", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zscan", {"zscan", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zpopmin", {"zpopmin", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"zpopmax", {"zpopmax", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"bzpopmin", {"bzpopmin", -3, WRITE_FLAG, 1, -2, 1}});
  RedisCommandTable->insert(
      {"bzpopmax", {"bzpopmax", -3, WRITE_FLAG, 1, -2, 1}});
  RedisCommandTable->insert(
      {"zrandmember", {"zrandmember", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hset", {"hset", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hsetnx", {"hsetnx", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hget", {"hget", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hmset", {"hmset", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hmget", {"hmget", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hincrby", {"hincrby", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"hincrbyfloat", {"hincrbyfloat", 4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hdel", {"hdel", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hlen", {"hlen", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"hstrlen", {"hstrlen", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hkeys", {"hkeys", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hvals", {"hvals", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"hgetall", {"hgetall", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"hexists", {"hexists", 3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"hrandfield", {"hrandfield", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"hscan", {"hscan", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"incrby", {"incrby", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"decrby", {"decrby", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"incrbyfloat", {"incrbyfloat", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"getset", {"getset", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"mset", {"mset", -3, WRITE_FLAG, 1, -1, 2}});
  RedisCommandTable->insert({"msetnx", {"msetnx", -3, WRITE_FLAG, 1, -1, 2}});
  RedisCommandTable->insert(
      {"randomkey", {"randomkey", 1, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"select", {"select", 2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"swapdb", {"swapdb", 3, WRITE_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"move", {"move", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"copy", {"copy", -3, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"rename", {"rename", 3, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"renamenx", {"renamenx", 3, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert({"expire", {"expire", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"expireat", {"expireat", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"pexpire", {"pexpire", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"pexpireat", {"pexpireat", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"keys", {"keys", 2, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"scan", {"scan", -2, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"dbsize", {"dbsize", 1, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"auth", {"auth", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"ping", {"ping", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"echo", {"echo", 2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"save", {"save", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"bgsave", {"bgsave", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"bgrewriteaof", {"bgrewriteaof", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"shutdown", {"shutdown", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"lastsave", {"lastsave", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"type", {"type", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"multi", {"multi", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"exec", {"exec", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"discard", {"discard", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"sync", {"sync", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"psync", {"psync", -3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"replconf", {"replconf", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"flushdb", {"flushdb", -1, WRITE_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"flushall", {"flushall", -1, WRITE_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"sort", {"sort", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"info", {"info", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"monitor", {"monitor", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"ttl", {"ttl", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"touch", {"touch", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"pttl", {"pttl", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"expiretime", {"expiretime", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"pexpiretime", {"pexpiretime", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"persist", {"persist", 2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"slaveof", {"slaveof", 3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"replicaof", {"replicaof", 3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"role", {"role", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"debug", {"debug", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"config", {"config", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"subscribe", {"subscribe", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"unsubscribe", {"unsubscribe", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"psubscribe", {"psubscribe", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"punsubscribe", {"punsubscribe", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"publish", {"publish", 3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"pubsub", {"pubsub", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"watch", {"watch", -2, ADMIN_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"unwatch", {"unwatch", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"cluster", {"cluster", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"restore", {"restore", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"restore-asking", {"restore-asking", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"migrate", {"migrate", -6, WRITE_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"asking", {"asking", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"readonly", {"readonly", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"readwrite", {"readwrite", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"dump", {"dump", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"object", {"object", -2, READONLY_FLAG, 2, 2, 1}});
  RedisCommandTable->insert({"memory", {"memory", -2, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"client", {"client", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"hello", {"hello", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"eval", {"eval", -3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"eval_ro", {"eval_ro", -3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"evalsha", {"evalsha", -3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"evalsha_ro", {"evalsha_ro", -3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"slowlog", {"slowlog", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"script", {"script", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"time", {"time", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"bitop", {"bitop", -4, WRITE_FLAG, 2, -1, 1}});
  RedisCommandTable->insert(
      {"bitcount", {"bitcount", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"bitpos", {"bitpos", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"wait", {"wait", 3, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"command", {"command", -1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"geoadd", {"geoadd", -5, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"georadius", {"georadius", -6, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"georadius_ro", {"georadius_ro", -6, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"georadiusbymember", {"georadiusbymember", -5, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"georadiusbymember_ro",
       {"georadiusbymember_ro", -5, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"geohash", {"geohash", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"geopos", {"geopos", -2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"geodist", {"geodist", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"geosearch", {"geosearch", -7, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"geosearchstore", {"geosearchstore", -8, WRITE_FLAG, 1, 2, 1}});
  RedisCommandTable->insert(
      {"pfselftest", {"pfselftest", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"pfadd", {"pfadd", -2, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"pfcount", {"pfcount", -2, READONLY_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"pfmerge", {"pfmerge", -2, WRITE_FLAG, 1, -1, 1}});
  RedisCommandTable->insert({"pfdebug", {"pfdebug", -3, ADMIN_FLAG, 2, 2, 1}});
  RedisCommandTable->insert({"xadd", {"xadd", -5, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xrange", {"xrange", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"xrevrange", {"xrevrange", -4, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xlen", {"xlen", 2, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xread", {"xread", -4, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"xreadgroup", {"xreadgroup", -7, WRITE_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"xgroup", {"xgroup", -2, WRITE_FLAG, 2, 2, 1}});
  RedisCommandTable->insert({"xsetid", {"xsetid", 3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xack", {"xack", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"xpending", {"xpending", -3, READONLY_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xclaim", {"xclaim", -6, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert(
      {"xautoclaim", {"xautoclaim", -6, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xinfo", {"xinfo", -2, READONLY_FLAG, 2, 2, 1}});
  RedisCommandTable->insert({"xdel", {"xdel", -3, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"xtrim", {"xtrim", -4, WRITE_FLAG, 1, 1, 1}});
  RedisCommandTable->insert({"post", {"post", -1, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"host:", {"host:", -1, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"latency", {"latency", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"lolwut", {"lolwut", -1, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"acl", {"acl", -2, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"stralgo", {"stralgo", -2, READONLY_FLAG, 0, 0, 0}});
  RedisCommandTable->insert({"reset", {"reset", 1, ADMIN_FLAG, 0, 0, 0}});
  RedisCommandTable->insert(
      {"failover", {"failover", -1, ADMIN_FLAG, 0, 0, 0}});
}