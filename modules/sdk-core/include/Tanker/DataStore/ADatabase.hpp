#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional.hpp>

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

  tc::cotask<void> inTransaction(std::function<tc::cotask<void>()> const& f)
  {
    TLOG_CATEGORY("ADatabase");
    TC_AWAIT(startTransaction());
    bool transaction = true;
    try
    {
      TC_AWAIT(f());
      transaction = false;
      TC_AWAIT(commitTransaction());
    }
    catch (...)
    {
      if (transaction)
      {
        try
        {
          TC_AWAIT(rollbackTransaction());
        }
        catch (std::exception const& e)
        {
          TERROR("Failed to rollback transaction: {}", e.what());
        }
        catch (...)
        {
          TERROR("Failed to rollback transaction: unknown error");
        }
      }
      throw;
    }
  }

  virtual tc::cotask<void> putUserPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey) = 0;
  virtual tc::cotask<Crypto::EncryptionKeyPair> getUserKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) = 0;
  virtual tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
  getUserOptLastKeyPair() = 0;

  virtual tc::cotask<uint64_t> getTrustchainLastIndex() = 0;
  virtual tc::cotask<void> addTrustchainEntry(Entry const& Entry) = 0;
  virtual tc::cotask<nonstd::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) const = 0;
  virtual tc::cotask<nonstd::optional<Entry>> findTrustchainKeyPublish(
      Crypto::Mac const& resourceId) = 0;
  virtual tc::cotask<std::vector<Entry>> getTrustchainDevicesOf(
      UserId const& userId) = 0;
  virtual tc::cotask<Entry> getTrustchainDevice(DeviceId const& deviceId) = 0;

  virtual tc::cotask<void> putContact(
      UserId const& userId,
      nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey) = 0;

  virtual tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>>
  getContactUserKey(UserId const& userId) = 0;

  virtual tc::cotask<void> putResourceKey(Crypto::Mac const& mac,
                                          Crypto::SymmetricKey const& key) = 0;
  virtual tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findResourceKey(
      Crypto::Mac const& mac) = 0;

  virtual tc::cotask<nonstd::optional<DeviceKeys>> getDeviceKeys() = 0;
  virtual tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) = 0;
  virtual tc::cotask<void> setDeviceId(DeviceId const& deviceId) = 0;

  virtual tc::cotask<void> putDevice(UserId const& userId,
                                     Device const& device) = 0;
  virtual tc::cotask<nonstd::optional<Device>> getOptDevice(
      DeviceId const& id) const = 0;
  virtual tc::cotask<std::vector<Device>> getDevicesOf(
      UserId const& id) const = 0;

  virtual tc::cotask<void> putFullGroup(Group const& group) = 0;
  virtual tc::cotask<void> putExternalGroup(ExternalGroup const& group) = 0;
  // Does nothing if the group does not exist
  virtual tc::cotask<void> updateLastGroupBlock(
      GroupId const& groupId,
      Crypto::Hash const& lastBlockHash,
      uint64_t lastBlockIndex) = 0;
  virtual tc::cotask<nonstd::optional<Group>> findFullGroupByGroupId(
      GroupId const& groupId) const = 0;
  virtual tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupId(GroupId const& groupId) const = 0;
  virtual tc::cotask<nonstd::optional<Group>>
  findFullGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const = 0;
  virtual tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const = 0;

protected:
  virtual tc::cotask<void> startTransaction() = 0;
  virtual tc::cotask<void> commitTransaction() = 0;
  virtual tc::cotask<void> rollbackTransaction() = 0;
};

using DatabasePtr = std::unique_ptr<ADatabase>;

tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    nonstd::optional<Crypto::SymmetricKey> const& userSecret = {},
    bool exclusive = true);
}
}
