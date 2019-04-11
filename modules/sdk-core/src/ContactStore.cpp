#include <Tanker/ContactStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/User.hpp>

#include <fmt/format.h>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

#include <stdexcept>
#include <utility>

namespace Tanker
{
ContactStore::ContactStore(DataStore::ADatabase* db) : _db(db)
{
}

tc::cotask<void> ContactStore::putUser(User const& user)
{
  assert(!user.devices.empty());

  if (!TC_AWAIT(_db->getDevicesOf(user.id)).empty())
  {
    throw Error::formatEx<std::runtime_error>(
        fmt("User {:s} is already stored"), user.id);
  }

  TC_AWAIT(_db->putContact(user.id, user.userKey));
  for (auto const& device : user.devices)
    TC_AWAIT(_db->putDevice(user.id, device));
}

tc::cotask<void> ContactStore::putUserKey(
    UserId const& userId, Crypto::PublicEncryptionKey const& userKey)
{
  TC_AWAIT(_db->putContact(userId, userKey));
}

tc::cotask<void> ContactStore::putUserDevice(UserId const& userId,
                                             Device const& device)
{
  TC_AWAIT(_db->putDevice(userId, device));
}

tc::cotask<nonstd::optional<User>> ContactStore::findUser(
    UserId const& id) const
{
  auto devices = TC_AWAIT(_db->getDevicesOf(id));
  if (devices.empty())
    TC_RETURN(nonstd::nullopt);

  auto userKey = TC_AWAIT(_db->findContactUserKey(id));
  TC_RETURN((User{id, std::move(userKey), std::move(devices)}));
}

tc::cotask<nonstd::optional<Device>> ContactStore::findDevice(
    DeviceId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->findDevice(id)));
}

tc::cotask<std::vector<Device>> ContactStore::findUserDevices(
    UserId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->getDevicesOf(id)));
}

tc::cotask<nonstd::optional<UserId>> ContactStore::findUserIdByUserPublicKey(
    Crypto::PublicEncryptionKey const& userKey) const
{
  TC_RETURN(TC_AWAIT(_db->findContactUserIdByPublicEncryptionKey(userKey)));
}

tc::cotask<nonstd::optional<UserId>> ContactStore::findUserIdByDeviceId(
    DeviceId const& id) const
{
  TC_RETURN(TC_AWAIT(_db->findDeviceUserId(id)));
}

tc::cotask<void> ContactStore::revokeDevice(DeviceId const& id,
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
