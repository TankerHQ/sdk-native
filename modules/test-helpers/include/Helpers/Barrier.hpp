#pragma once

#ifdef __MINGW32__
#include <mingw-threads/mingw.thread.h>
#include <mingw-threads/mingw.condition_variable.h>
#else
#include <condition_variable>
#include <mutex>
#endif

namespace Tanker
{
class Barrier
{
public:
  Barrier(Barrier const&) = delete;
  Barrier(Barrier&&) = delete;
  Barrier& operator=(Barrier const&) = delete;
  Barrier& operator=(Barrier&&) = delete;

  Barrier(unsigned int max);
  void operator()();

private:
  using Mutex = std::mutex;
  using ScopeLock = std::unique_lock<Mutex>;

  Mutex _mutex;
  std::condition_variable _cond;

  const unsigned int _max;
  unsigned int _waiting = 0;
};
}
