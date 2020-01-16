#pragma once

#include <tconcurrent/async_wait.hpp>

#include <vector>

template <typename T = void>
tc::cotask<void> waitFor(tc::promise<T> prom)
{
  std::vector<tc::future<void>> futures;
  futures.push_back(prom.get_future());
  futures.push_back(tc::async_wait(std::chrono::seconds(2)));
  auto const result =
      TC_AWAIT(tc::when_any(std::make_move_iterator(futures.begin()),
                            std::make_move_iterator(futures.end()),
                            tc::when_any_options::auto_cancel));
  if (result.index != 0)
    throw std::runtime_error("timeout waiting for promise");
}