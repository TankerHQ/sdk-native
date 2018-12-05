#include <Helpers/Barrier.hpp>

#include <cassert>

namespace Tanker
{
Barrier::Barrier(unsigned int max) : _max(max)
{
}

void Barrier::operator()()
{
  bool done;
  {
    ScopeLock lock(_mutex);
    ++_waiting;
    assert(_waiting <= _max);

    done = _waiting == _max;

    if (!done)
      _cond.wait(lock, [&] { return _waiting == _max; });
  }

  if (done)
    _cond.notify_all();
}
}
