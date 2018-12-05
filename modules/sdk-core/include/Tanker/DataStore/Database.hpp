#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
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

class Database
{
public:
  explicit Database(std::string const& dbPath,
                    nonstd::optional<Crypto::SymmetricKey> const& userSecret,
                    bool exclusive);

  Connection* getConnection();

  tc::cotask<void> putUserPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey);
  tc::cotask<Crypto::EncryptionKeyPair> getUserKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) const;
  tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
  getUserOptLastKeyPair() const;

  tc::cotask<uint64_t> getTrustchainLastIndex() const;
  tc::cotask<void> addTrustchainEntry(Entry const& Entry);
  tc::cotask<nonstd::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) const;
  tc::cotask<nonstd::optional<Entry>> findTrustchainKeyPublish(
      Crypto::Mac const& resourceId) const;
  tc::cotask<std::vector<Entry>> getTrustchainDevicesOf(
      UserId const& userId) const;
  tc::cotask<Entry> getTrustchainDevice(DeviceId const& deviceId) const;

  tc::cotask<void> putContact(
      UserId const& userId,
      nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey);

  tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>> getContactUserKey(
      UserId const& userId) const;
  tc::cotask<nonstd::optional<UserId>> getContactUserId(
      Crypto::PublicEncryptionKey const& userPublicKey) const;
  tc::cotask<void> setPublicEncryptionKey(
      UserId const& userId, Crypto::PublicEncryptionKey const& userPublicKey);

  tc::cotask<void> putResourceKey(Crypto::Mac const& mac,
                                  Crypto::SymmetricKey const& key);
  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findResourceKey(
      Crypto::Mac const& mac) const;

  tc::cotask<nonstd::optional<DeviceKeys>> getDeviceKeys() const;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys);
  tc::cotask<void> setDeviceId(DeviceId const& deviceId);

  tc::cotask<void> putDevice(UserId const& userId, Device const& device);
  tc::cotask<nonstd::optional<Device>> getOptDevice(DeviceId const& id) const;
  tc::cotask<std::vector<Device>> getDevicesOf(UserId const& id) const;
  tc::cotask<nonstd::optional<UserId>> getDeviceUserId(
      DeviceId const& id) const;
  tc::cotask<void> updateDeviceRevokedAt(DeviceId const& id,
                                         uint64_t revokedAtBlkIndex) const;

  tc::cotask<void> putFullGroup(Group const& group);
  tc::cotask<void> putExternalGroup(ExternalGroup const& group);
  // Does nothing if the group does not exist
  tc::cotask<void> updateLastGroupBlock(GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex);
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupId(
      GroupId const& groupId) const;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalGroupByGroupId(
      GroupId const& groupId) const;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;
  tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const;

  tc::cotask<void> nuke();

private:
  ConnPtr _db;

  bool isMigrationNeeded() const;
  void flushAllCaches();
  tc::cotask<void> indexKeyPublish(Crypto::Hash const& hash,
                                   Crypto::Mac const& resourceId);
};

using DatabasePtr = std::unique_ptr<Database>;

inline tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    nonstd::optional<Crypto::SymmetricKey> const& userSecret = {},
    bool exclusive = true)
{
  TC_RETURN(std::make_unique<Database>(dbPath, userSecret, exclusive));
}
}
}
