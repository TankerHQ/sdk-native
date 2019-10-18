#pragma once

#include <condition_variable>
#include <mutex>

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
