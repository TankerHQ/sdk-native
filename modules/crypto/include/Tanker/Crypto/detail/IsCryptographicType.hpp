#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <type_traits>

#define TANKER_CRYPTO_IS_CRYPTOGRAPHIC_TYPE(Self)   \
  template <>                                       \
  struct IsCryptographicType<Self> : std::true_type \
  {                                                 \
  };
