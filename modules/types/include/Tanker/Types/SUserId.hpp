#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/StringWrapper.hpp>

#include <cstdint>

namespace Tanker
{
using SUserId = StringWrapper<struct UserIdTag>;

inline Trustchain::UserId obfuscateUserId(
    SUserId const& s, Trustchain::TrustchainId const& trustchainId)
{
  std::vector<std::uint8_t> toHash;

  toHash.reserve(s.size() + trustchainId.size());
  toHash.insert(toHash.end(), s.begin(), s.end());
  toHash.insert(toHash.end(), trustchainId.begin(), trustchainId.end());
  return Crypto::generichash<Trustchain::UserId>(toHash);
}

namespace type_literals
{
inline SUserId operator""_uid(const char* s, std::size_t t)
{
  return SUserId(s, t);
}
}
}
