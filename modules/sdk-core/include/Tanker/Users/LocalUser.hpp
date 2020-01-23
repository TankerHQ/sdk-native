#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <optional>

namespace Tanker::DataStore
{
class ADatabase;
}

namespace Tanker::Users
{

class LocalUser
{
public:
  using Ptr = std::unique_ptr<LocalUser>;
  LocalUser(LocalUser const&) = delete;
  LocalUser(LocalUser&&) = delete;
  LocalUser& operator=(LocalUser const&) = delete;
  LocalUser& operator=(LocalUser&&) = delete;

  LocalUser(Trustchain::UserId const& userId,
            Trustchain::DeviceId const& deviceId,
            DeviceKeys const& deviceKeys,
            DataStore::ADatabase* dbCon);

  static tc::cotask<Ptr> open(Identity::SecretPermanentIdentity const&,
                              DataStore::ADatabase* dbcon);

  Trustchain::DeviceId const& deviceId() const;
  DeviceKeys const& deviceKeys() const;
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);
  Trustchain::UserId const& userId() const;
  tc::cotask<Crypto::EncryptionKeyPair> currentKeyPair() const;
  tc::cotask<void> insertUserKey(
      Crypto::EncryptionKeyPair const& userEncryptionKey);
  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> findKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) const;

private:
  Trustchain::UserId _userId;
  Trustchain::DeviceId _deviceId;
  DeviceKeys _deviceKeys;
  DataStore::ADatabase* _db;
};
}