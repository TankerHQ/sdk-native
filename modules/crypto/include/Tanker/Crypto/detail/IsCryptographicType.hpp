#pragma once

#include <Tanker/Crypto/Traits.hpp>

#include <type_traits>

#define TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(Self)     \
  template <>                                         \
  struct is_cryptographic_type<Self> : std::true_type \
  {                                                   \
  };
