#pragma once

#include <atomic>
#include <chrono>

template <typename S>
std::size_t WaitForSignal(S&& sig, std::size_t counter = 1)
{
  std::atomic<std::size_t> triggered{0};

  auto conn = sig.connect([&triggered] { ++triggered; });
  auto const start = std::chrono::steady_clock::now();
  while (triggered < counter)
  {
    auto const now = std::chrono::steady_clock::now();
    if (start + std::chrono::seconds(5) < now)
    {
      break;
    }
  }

  conn.disconnect();
  return triggered;
}
