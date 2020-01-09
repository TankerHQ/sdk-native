#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
template <typename T, typename U>
T& extract(U& action)
{
  return const_cast<T&>(action.template get<T>());
}

template <typename T, typename U, typename V>
U& unconstify(T& action, U const& (V::*method)() const)
{
  auto const& subAction = action.template get<V>();
  return const_cast<U&>((subAction.*method)());
}

template <typename T, typename U>
U& unconstify(T& action, U const& (T::*method)() const)
{
  return const_cast<U&>((action.*method)());
}

template <typename T>
void alter(ServerEntry& entry, T const& (ServerEntry::*method)() const)
{
  ++unconstify(entry, method)[0];
}

template <typename T, typename U, typename V>
void alter(T& action, U const& (V::*method)() const)
{
  ++unconstify(action, method)[0];
}

template <typename T, typename U>
void alter(T& action, U const& (T::*method)() const)
{
  ++unconstify(action, method)[0];
}
}
