#pragma once

#include <condition_variable>
#include <mutex>

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
