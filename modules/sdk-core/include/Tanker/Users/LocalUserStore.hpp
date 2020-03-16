#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
struct DeviceKeys;

namespace DataStore
{
class ADatabase;
}

namespace Users
{
class LocalUserStore
{
public:
  LocalUserStore(DataStore::ADatabase* dbCon);

  tc::cotask<void> putLocalUser(LocalUser const& user);
  tc::cotask<void> putUserKeys(
      gsl::span<Crypto::EncryptionKeyPair const> userKeys);

  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() const;
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const& sigKey);
  tc::cotask<std::optional<LocalUser>> findLocalUser(
      Trustchain::UserId const& userId) const;
  tc::cotask<DeviceKeys> getDeviceKeys() const;

private:
  DataStore::ADatabase* _dbCon;
};
}
}