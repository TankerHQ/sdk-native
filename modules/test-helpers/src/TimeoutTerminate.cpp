#include <Helpers/TimeoutTerminate.hpp>

#include <cstdlib>
#include <iostream>

namespace Tanker
{
TimeoutTerminate::TimeoutTerminate(std::chrono::steady_clock::duration timeout)
  : _timeout(timeout), _thread(&TimeoutTerminate::runTimeout, this)
{
}

TimeoutTerminate::~TimeoutTerminate()
{
  _done = true;
  _thread.join();
}

void TimeoutTerminate::runTimeout()
{
  static constexpr auto Step = std::chrono::milliseconds(100);

  auto const start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < _timeout)
  {
    std::this_thread::sleep_for(Step);
    if (_done.load())
      return;
  }
  std::cerr << "the " << std::chrono::duration_cast<std::chrono::seconds>(_timeout).count()
            << "s timeout was reached, exiting";
  std::_Exit(1);
}
}
