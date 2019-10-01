#pragma once

#include <atomic>
#include <chrono>

#ifdef __MINGW32__
#include <mingw-threads/mingw.thread.h>
#else
#include <thread>
#endif

namespace Tanker
{
class TimeoutTerminate
{
public:
  TimeoutTerminate(TimeoutTerminate&&) = delete;
  TimeoutTerminate(TimeoutTerminate const&) = delete;
  TimeoutTerminate& operator=(TimeoutTerminate&&) = delete;
  TimeoutTerminate& operator=(TimeoutTerminate const&) = delete;

  TimeoutTerminate(std::chrono::steady_clock::duration timeout);

  ~TimeoutTerminate();

private:
  std::chrono::steady_clock::duration _timeout;
  std::atomic<bool> _done{false};
  std::thread _thread;

  void runTimeout();
};
}
