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
class Stepper
{
public:
  Stepper(Stepper const&) = delete;
  Stepper(Stepper&&) = delete;
  Stepper& operator=(Stepper const&) = delete;
  Stepper& operator=(Stepper&&) = delete;

  Stepper() = default;

  void operator()(unsigned int step);

private:
  using Mutex = std::mutex;
  using ScopeLock = std::unique_lock<Mutex>;

  Mutex _mutex;
  std::condition_variable _cond;

  unsigned int _step = 0;
};
}
