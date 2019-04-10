#pragma once

#include <Tanker/Crypto/detail/CryptographicTypeImpl.hpp>

#include <array>
#include <cstdint>

#define TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE(name, size)        \
  class name : std::array<std::uint8_t, size>               \
  {                                                         \
    TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE_IMPL(name, size, name) \
  };
