#include <Tanker/Retry.hpp>

#include <Tanker/Errors/Exception.hpp>

#include <tconcurrent/async_wait.hpp>

#include <random>

namespace Tanker
{
DelayList exponentialDelays(int retries)
{
  static std::mt19937 generator{std::random_device()()};
  std::uniform_int_distribution<int> uniform(0, 1000);

  DelayList ret;
  for (auto attempts = 0; attempts < retries; ++attempts)
  {
    auto const seconds = std::chrono::seconds(1 << attempts);
    auto const rand = std::chrono::milliseconds(uniform(generator));
    ret.push_back(seconds + rand);
  }
  return ret;
}

tc::cotask<void> retry(std::function<tc::cotask<void>()> f,
                       DelayList const& delays)
{
  auto i = 0u;
  while (true)
  {
    try
    {
      TC_AWAIT(f());
      TC_RETURN();
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() != Errors::Errc::NetworkError)
        throw;
      if (i == delays.size())
        throw;
    }

    TC_AWAIT(tc::async_wait(delays[i]));
    ++i;
  }
}
}
