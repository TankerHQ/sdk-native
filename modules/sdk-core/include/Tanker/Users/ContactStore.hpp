#pragma once

#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/User.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class ADatabase;
}

namespace Users
{
struct Device;
class ContactStore
{
public:
  ContactStore(DataStore::ADatabase* dbConn);

  ContactStore() = delete;
  ContactStore(Users::ContactStore const&) = delete;
  ContactStore(Users::ContactStore&&) = delete;
  Users::ContactStore& operator=(Users::ContactStore const&) = delete;
  Users::ContactStore& operator=(Users::ContactStore&&) = delete;
  ~ContactStore() = default;

  tc::cotask<void> putUser(User const& user);
  tc::cotask<void> putUserKey(Trustchain::UserId const& id,
                              Crypto::PublicEncryptionKey const& userKey);
  tc::cotask<void> putUserDevice(Users::Device const& device);

  tc::cotask<std::optional<User>> findUser(Trustchain::UserId const& id) const;
  tc::cotask<std::optional<Users::Device>> findDevice(
      Trustchain::DeviceId const& id) const;
  tc::cotask<std::vector<Users::Device>> findUserDevices(
      Trustchain::UserId const& id) const;
  tc::cotask<std::optional<Trustchain::UserId>> findUserIdByUserPublicKey(
      Crypto::PublicEncryptionKey const& userKey) const;
  tc::cotask<std::optional<Trustchain::UserId>> findUserIdByDeviceId(
      Trustchain::DeviceId const& id) const;

  tc::cotask<void> revokeDevice(Trustchain::DeviceId const& id,
                                uint64_t revokedAtBlkIndex) const;
  tc::cotask<void> rotateContactPublicEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) const;

private:
  DataStore::ADatabase* _db;
};
}
}
