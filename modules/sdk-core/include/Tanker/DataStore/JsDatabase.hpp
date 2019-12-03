#pragma once

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
namespace DataStore
{
class JsDatabaseInterface;

class JsDatabase : public ADatabase
{
public:
  explicit JsDatabase();
  ~JsDatabase();

  tc::cotask<void> open(std::string const& dbName);

  tc::cotask<void> putUserPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey) override;
  tc::cotask<Crypto::EncryptionKeyPair> getUserKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) override;
  tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
  getUserOptLastKeyPair() override;

  tc::cotask<std::optional<uint64_t>> findTrustchainLastIndex() override;
  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() override;
  tc::cotask<void> setTrustchainLastIndex(uint64_t) override;
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const&) override;
  tc::cotask<void> addTrustchainEntry(Entry const& Entry) override;
  tc::cotask<std::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) override;

  tc::cotask<void> putContact(
      Trustchain::UserId const& userId,
      std::optional<Crypto::PublicEncryptionKey> const& publicKey) override;

  tc::cotask<std::optional<Crypto::PublicEncryptionKey>> findContactUserKey(
      Trustchain::UserId const& userId) override;
  tc::cotask<std::optional<Trustchain::UserId>>
  findContactUserIdByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& userPublicKey) override;
  tc::cotask<void> setContactPublicEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) override;

  tc::cotask<void> putKeyPublishes(
      gsl::span<Trustchain::Actions::KeyPublish const>) override;
  tc::cotask<std::optional<Trustchain::Actions::KeyPublish>> findKeyPublish(
      Trustchain::ResourceId const&) override;

  tc::cotask<void> putResourceKey(Trustchain::ResourceId const& resourceId,
                                  Crypto::SymmetricKey const& key) override;
  tc::cotask<std::optional<Crypto::SymmetricKey>> findResourceKey(
      Trustchain::ResourceId const& resourceId) override;

  tc::cotask<std::optional<DeviceKeys>> getDeviceKeys() override;
  tc::cotask<std::optional<Trustchain::DeviceId>> getDeviceId() override;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) override;
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId) override;

  tc::cotask<void> putDevice(Trustchain::UserId const& userId,
                             Device const& device) override;
  tc::cotask<std::optional<Device>> findDevice(
      Trustchain::DeviceId const& id) override;
  tc::cotask<std::vector<Device>> getDevicesOf(
      Trustchain::UserId const& id) override;
  tc::cotask<std::optional<Trustchain::UserId>> findDeviceUserId(
      Trustchain::DeviceId const& id) override;
  tc::cotask<void> updateDeviceRevokedAt(Trustchain::DeviceId const& id,
                                         uint64_t revokedAtBlkIndex) override;

  tc::cotask<void> putInternalGroup(InternalGroup const& group) override;
  tc::cotask<void> putExternalGroup(ExternalGroup const& group) override;
  tc::cotask<void> putGroupProvisionalEncryptionKeys(
      Trustchain::GroupId const& groupId,
      std::vector<GroupProvisionalUser> const& provisionalUsers) override;
  // Does nothing if the group does not exist
  tc::cotask<void> updateLastGroupBlock(Trustchain::GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex) override;
  tc::cotask<std::optional<InternalGroup>> findInternalGroupByGroupId(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<std::optional<ExternalGroup>> findExternalGroupByGroupId(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<std::vector<ExternalGroup>> findExternalGroupsByProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey) override;
  tc::cotask<std::optional<InternalGroup>> findInternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;
  tc::cotask<std::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;
  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys) override;
  tc::cotask<std::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;
  tc::cotask<std::optional<ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncKey) override;

  tc::cotask<void> nuke() override;

private:
  std::unique_ptr<JsDatabaseInterface> _db;

  tc::cotask<void> startTransaction() override;
  tc::cotask<void> commitTransaction() override;
  tc::cotask<void> rollbackTransaction() override;
};
}
}
