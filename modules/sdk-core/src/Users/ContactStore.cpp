#include <Tanker/Users/ContactStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>

#include <stdexcept>
#include <utility>

using Tanker::Trustchain::UserId;

namespace Tanker::Users
{
ContactStore::ContactStore(DataStore::ADatabase* db) : _db(db)
{
}

tc::cotask<void> ContactStore::putUser(User const& user)
{
  assert(!user.devices().empty());

  TC_AWAIT(_db->putContact(user.id(), user.userKey()));
  for (auto const& device : user.devices())
  {
    assert(user.id() == device.userId());
    TC_AWAIT(_db->putDevice(device));
  }
}

tc::cotask<void> ContactStore::putUserKey(
    UserId const& userId, Crypto::PublicEncryptionKey const& userKey)
{
  TC_AWAIT(_db->putContact(userId, userKey));
}

tc::cotask<void> ContactStore::putUserDevice(Device const& device)
{
  TC_AWAIT(_db->putDevice(device));
}

tc::cotask<std::optional<User>> ContactStore::findUser(UserId const& id) const
{
  auto devices = TC_AWAIT(_db->getDevicesOf(id));
  if (devices.empty())
    TC_RETURN(std::nullopt);

  auto userKey = TC_AWAIT(_db->findContactUserKey(id));
  TC_RETURN((User{id, std::move(userKey), std::move(devices)}));
}

tc::cotask<std::optional<Device>> ContactStore::findDevice(
    Trustchain::DeviceId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->findDevice(id)));
}

tc::cotask<std::vector<Device>> ContactStore::findUserDevices(
    UserId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->getDevicesOf(id)));
}

tc::cotask<std::optional<UserId>> ContactStore::findUserIdByUserPublicKey(
    Crypto::PublicEncryptionKey const& userKey) const
{
  TC_RETURN(TC_AWAIT(_db->findContactUserIdByPublicEncryptionKey(userKey)));
}

tc::cotask<std::optional<UserId>> ContactStore::findUserIdByDeviceId(
    Trustchain::DeviceId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->findDeviceUserId(id)));
}

tc::cotask<void> ContactStore::revokeDevice(Trustchain::DeviceId const& id,
                                            uint64_t revokedAtBlkIndex) const
{
  TC_AWAIT(_db->updateDeviceRevokedAt(id, revokedAtBlkIndex));
}

tc::cotask<void> ContactStore::rotateContactPublicEncryptionKey(
    UserId const& userId,
    Crypto::PublicEncryptionKey const& userPublicKey) const
{
  TC_AWAIT(_db->setContactPublicEncryptionKey(userId, userPublicKey));
}
}
