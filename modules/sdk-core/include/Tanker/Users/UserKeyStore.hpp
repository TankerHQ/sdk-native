#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker::DataStore
{
class ADatabase;
}

namespace Tanker::Users
{
class UserKeyStore
{
public:
  UserKeyStore(UserKeyStore const&) = delete;
  UserKeyStore(UserKeyStore&&) = delete;
  UserKeyStore& operator=(UserKeyStore const&) = delete;
  UserKeyStore& operator=(UserKeyStore&&) = delete;

  UserKeyStore(DataStore::ADatabase* dbConn);

  tc::cotask<void> putPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey);
  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> findKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) const;
  tc::cotask<Crypto::EncryptionKeyPair> getKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) const;

  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> getOptLastKeyPair()
      const;
  tc::cotask<Crypto::EncryptionKeyPair> getLastKeyPair() const;
  tc::cotask<bool> isEmpty() const;

private:
  DataStore::ADatabase* _db;
};
}
