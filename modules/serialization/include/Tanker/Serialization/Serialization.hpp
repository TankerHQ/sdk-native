#pragma once

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/from_serialized.hpp>
#include <Tanker/Serialization/serialized_size.hpp>
#include <Tanker/Serialization/to_serialized.hpp>

#include <cassert>
#include <cstdint>
#include <type_traits>
#include <vector>

namespace Tanker
{
namespace Serialization
{
template <typename T>
std::vector<std::uint8_t> serialize(T const& val)
{
  std::vector<std::uint8_t> buffer;
  auto const size = serialized_size(val);
  buffer.resize(size);
  auto const it = to_serialized(buffer.data(), val);
  assert(it == buffer.data() + size);
  (void)it;
  return buffer;
}

template <typename T>
std::uint8_t* serialize(std::uint8_t* it, T const& val)
{
  return to_serialized(it, val);
}

template <typename T>
void deserialize_to(SerializedSource& ss, T& val)
{
  detail::deserialize_impl(ss, val);
}

template <typename T>
T deserialize(SerializedSource& ss)
{
  T ret;
  deserialize_to(ss, ret);
  return ret;
}

template <typename T>
void deserialize_to(gsl::span<std::uint8_t const> serialized, T& val)
{
  SerializedSource ss{serialized};

  deserialize_to(ss, val);
  if (!ss.eof())
  {
    throw Errors::formatEx(Errc::TrailingInput, "{} trailing bytes", ss.remaining_size());
  }
}

template <typename T>
T deserialize(gsl::span<std::uint8_t const> serialized)
{
  T ret;
  deserialize_to(serialized, ret);
  return ret;
}
}
}
