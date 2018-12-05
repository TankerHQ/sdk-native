#include <Helpers/Stepper.hpp>

namespace Tanker
{
void Stepper::operator()(unsigned int step)
{
  {
    ScopeLock lock(_mutex);
    _cond.wait(lock, [&] { return step <= _step + 1; });
    ++_step;
  }
  _cond.notify_all();
}
}
