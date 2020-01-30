#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker::Users
{
class LocalUser;
class ILocalUserAccessor
{
public:
  virtual LocalUser const& get() const = 0;
  virtual tc::cotask<LocalUser const&> pull() = 0;
  virtual tc::cotask<std::optional<Crypto::EncryptionKeyPair>> pullUserKeyPair(
      Crypto::PublicEncryptionKey const& publicUserKey) = 0;
  virtual ~ILocalUserAccessor() = default;
};
}