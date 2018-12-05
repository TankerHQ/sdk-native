#pragma once

#include <boost/signals2.hpp>

#include <vector>

namespace Tanker
{
template <typename... T>
class SignalSpy
{
public:
  template <typename S>
  SignalSpy(S& signal)
    : _conn(signal.connect(
          [this](T const&... t) { receivedEvents.emplace_back(t...); }))
  {
  }

  std::vector<std::tuple<T...>> receivedEvents;

private:
  boost::signals2::scoped_connection _conn;
};

template <>
class SignalSpy<void>
{
public:
  template <typename S>
  SignalSpy(S& signal)
    : _conn(signal.connect([this]() { receivedEvents.emplace_back(0); }))
  {
  }

  std::vector<int> receivedEvents;

private:
  boost::signals2::scoped_connection _conn;
};
}
