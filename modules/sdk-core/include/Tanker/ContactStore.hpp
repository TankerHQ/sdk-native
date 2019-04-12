#pragma once

#include <Tanker/Types/UserId.hpp>
#include <Tanker/User.hpp>

#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class ADatabase;
}

struct Device;

class ContactStore
{
public:
  ContactStore(DataStore::ADatabase* dbConn);

  ContactStore() = delete;
  ContactStore(ContactStore const&) = delete;
  ContactStore(ContactStore&&) = delete;
  ContactStore& operator=(ContactStore const&) = delete;
  ContactStore& operator=(ContactStore&&) = delete;
  ~ContactStore() = default;

  tc::cotask<void> putUser(User const& user);
  tc::cotask<void> putUserKey(UserId const& id,
                              Crypto::PublicEncryptionKey const& userKey);
  tc::cotask<void> putUserDevice(UserId const& id, Device const& device);

  tc::cotask<nonstd::optional<User>> findUser(UserId const& id) const;
  tc::cotask<nonstd::optional<Device>> findDevice(DeviceId const& id) const;
  tc::cotask<std::vector<Device>> findUserDevices(UserId const& id) const;
  tc::cotask<nonstd::optional<UserId>> findUserIdByUserPublicKey(
      Crypto::PublicEncryptionKey const& userKey) const;
  tc::cotask<nonstd::optional<UserId>> findUserIdByDeviceId(
      DeviceId const& id) const;

  tc::cotask<void> revokeDevice(DeviceId const& id,
                                uint64_t revokedAtBlkIndex) const;
  tc::cotask<void> rotateContactPublicEncryptionKey(
      UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) const;

private:
  DataStore::ADatabase* _db;
};
}
