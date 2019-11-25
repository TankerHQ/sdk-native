#pragma once

#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
namespace ProvisionalUsers
{
class IAccessor
{
public:
  virtual ~IAccessor() = default;

  virtual tc::cotask<std::optional<ProvisionalUserKeys>> pullEncryptionKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) = 0;
  virtual tc::cotask<std::optional<ProvisionalUserKeys>>
  findEncryptionKeysFromCache(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) = 0;

  virtual tc::cotask<void> refreshKeys() = 0;
};
}
}
