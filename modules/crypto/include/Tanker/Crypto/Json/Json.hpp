#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <type_traits>

namespace nlohmann
{
template <typename CryptoType>
struct adl_serializer<
    CryptoType,
    std::enable_if_t<::Tanker::Crypto::IsCryptographicType<CryptoType>::value>>
{
  static void to_json(json& j, CryptoType const& value)
  {
    j = cppcodec::base64_rfc4648::encode(value);
  }

  static CryptoType from_json(json const& j)
  {
    return cppcodec::base64_rfc4648::decode<CryptoType>(j.get<std::string>());
  }

  static void from_json(json const& j, CryptoType& value)
  {
    value = adl_serializer<CryptoType>::from_json(j);
  }
};
}
