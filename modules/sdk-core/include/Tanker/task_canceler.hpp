#pragma once

#include <cassert>
#include <vector>

#include <tconcurrent/future.hpp>
#include <tconcurrent/when.hpp>

namespace Tanker
{
class task_canceler
{
public:
  ~task_canceler()
  {
    auto const fut = terminate(true);
    if (!fut.is_ready())
    {
      assert(false &&
             "destructing a task_canceler that could not be canceled");
      return;
    }
  }

  template <typename Func>
  decltype(std::declval<Func>()().to_shared()) run(Func&& func)
  {
    lock_guard _(_mutex);

    if (_terminating)
      throw std::runtime_error(
          "adding a future to terminating task_canceler");

    auto future = func().to_shared();

    if (!future.is_ready())
    {
      collect();
      _futures.emplace_back(future.to_void());
    }

    return future;
  }

  tc::future<void> terminate()
  {
    return terminate(false);
  }

private:
  using lock_guard = std::lock_guard<std::mutex>;
  std::mutex _mutex;
  std::vector<tc::shared_future<void>> _futures;
  bool _terminating{false};

  /// Remove ready futures from vector
  void collect()
  {
    _futures.erase(
        std::remove_if(_futures.begin(),
                       _futures.end(),
                       [](auto const& fut) { return fut.is_ready(); }),
        _futures.end());
  }

  tc::future<void> terminate(bool terminating)
  {
    lock_guard _(_mutex);

    if (terminating)
      _terminating = true;
    for (auto& fut : _futures)
      fut.request_cancel();
    auto ret = when_all(std::make_move_iterator(_futures.begin()),
                        std::make_move_iterator(_futures.end()))
                   .to_void();
    _futures.clear();
    // move ret, otherwise it doesn't compile
    // static_cast to silence a clang warning
    return static_cast<decltype(ret)&&>(ret);
  }
};
}
