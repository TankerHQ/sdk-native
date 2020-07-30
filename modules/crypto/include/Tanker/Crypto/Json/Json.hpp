#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json_fwd.hpp>

#include <string>
#include <type_traits>

namespace nlohmann
{
template <typename CryptoType>
struct adl_serializer<
    CryptoType,
    std::enable_if_t<::Tanker::Crypto::IsCryptographicType<CryptoType>::value>>
{
  template <typename Json>
  static void to_json(Json& j, CryptoType const& value)
  {
    j = mgs::base64::encode(value);
  }

  template <typename Json>
  static CryptoType from_json(Json const& j)
  {
    return mgs::base64::decode<CryptoType>(j.template get<std::string>());
  }

  template <typename Json>
  static void from_json(Json const& j, CryptoType& value)
  {
    value = adl_serializer<CryptoType>::template from_json(j);
  }
};
}
