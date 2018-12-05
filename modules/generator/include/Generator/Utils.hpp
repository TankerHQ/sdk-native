#pragma once

#include <Tanker/Crypto/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker
{
namespace Generator
{
std::vector<uint8_t> make_random_bytes(std::size_t size);

template <typename T>
T make_random_bytes()
{
  T buf;
  randombytes_buf(buf.data(), std::tuple_size<T>::value);
  return buf;
}
}
}
