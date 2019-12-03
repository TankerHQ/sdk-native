#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/GroupProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <gsl-lite.hpp>
#include <optional>
#include <tconcurrent/coroutine.hpp>

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace Tanker
{
namespace DataStore
{
class RecordNotFound : public std::exception
{
public:
  RecordNotFound(std::string msg) : _msg(std::move(msg))
  {
  }

  char const* what() const noexcept override
  {
    return _msg.c_str();
  }

private:
  std::string _msg;
};

class ADatabase
{
public:
  virtual ~ADatabase() = default;

  tc::cotask<void> inTransaction(std::function<tc::cotask<void>()> const& f);

  virtual tc::cotask<void> putUserPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey) = 0;
  virtual tc::cotask<Crypto::EncryptionKeyPair> getUserKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) = 0;
  virtual tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
  getUserOptLastKeyPair() = 0;

  virtual tc::cotask<std::optional<uint64_t>> findTrustchainLastIndex() = 0;
  virtual tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() = 0;
  virtual tc::cotask<void> setTrustchainLastIndex(uint64_t) = 0;
  virtual tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const&) = 0;
  virtual tc::cotask<void> addTrustchainEntry(Entry const& Entry) = 0;
  virtual tc::cotask<std::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) = 0;

  virtual tc::cotask<void> putContact(
      Trustchain::UserId const& userId,
      std::optional<Crypto::PublicEncryptionKey> const& publicKey) = 0;

  virtual tc::cotask<std::optional<Trustchain::Actions::KeyPublish>>
  findKeyPublish(Trustchain::ResourceId const&) = 0;

  virtual tc::cotask<std::optional<Crypto::PublicEncryptionKey>>
  findContactUserKey(Trustchain::UserId const& userId) = 0;
  virtual tc::cotask<std::optional<Trustchain::UserId>>
  findContactUserIdByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& userPublicKey) = 0;
  virtual tc::cotask<void> setContactPublicEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) = 0;

  virtual tc::cotask<void> putResourceKey(
      Trustchain::ResourceId const& resourceId,
      Crypto::SymmetricKey const& key) = 0;
  virtual tc::cotask<std::optional<Crypto::SymmetricKey>> findResourceKey(
      Trustchain::ResourceId const& resourceId) = 0;

  virtual tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys) = 0;
  virtual tc::cotask<std::optional<ProvisionalUserKeys>>
  findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) = 0;
  virtual tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncryptionKey) = 0;

  virtual tc::cotask<std::optional<DeviceKeys>> getDeviceKeys() = 0;
  virtual tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) = 0;
  virtual tc::cotask<void> setDeviceId(
      Trustchain::DeviceId const& deviceId) = 0;
  virtual tc::cotask<std::optional<Trustchain::DeviceId>> getDeviceId() = 0;

  virtual tc::cotask<void> putDevice(Trustchain::UserId const& userId,
                                     Device const& device) = 0;
  virtual tc::cotask<std::optional<Device>> findDevice(
      Trustchain::DeviceId const& id) = 0;
  virtual tc::cotask<std::vector<Device>> getDevicesOf(
      Trustchain::UserId const& id) = 0;
  virtual tc::cotask<std::optional<Trustchain::UserId>> findDeviceUserId(
      Trustchain::DeviceId const& id) = 0;
  virtual tc::cotask<void> updateDeviceRevokedAt(
      Trustchain::DeviceId const& id, uint64_t revokedAtBlkIndex) = 0;

  virtual tc::cotask<void> putInternalGroup(InternalGroup const& group) = 0;
  virtual tc::cotask<void> putExternalGroup(ExternalGroup const& group) = 0;
  virtual tc::cotask<std::optional<Group>> findGroupByGroupId(
      Trustchain::GroupId const& groupId) = 0;
  virtual tc::cotask<std::optional<Group>>
  findGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) = 0;

  virtual tc::cotask<void> nuke() = 0;

protected:
  virtual tc::cotask<void> startTransaction() = 0;
  virtual tc::cotask<void> commitTransaction() = 0;
  virtual tc::cotask<void> rollbackTransaction() = 0;
};

using DatabasePtr = std::unique_ptr<ADatabase>;

tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret = {},
    bool exclusive = true);
}
}
