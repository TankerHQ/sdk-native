#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/SUserId.hpp>

namespace Tanker
{

using UserId = Crypto::BasicHash<struct UserIdImpl>;

template <typename T>
UserId obfuscateUserId(SUserId const& s, Crypto::BasicHash<T> const& hash)
{
  std::vector<uint8_t> toHash;

  toHash.reserve(s.size() + hash.size());
  toHash.insert(toHash.end(), s.begin(), s.end());
  toHash.insert(toHash.end(), hash.begin(), hash.end());
  return Crypto::generichash<UserId>(toHash);
}
}
