#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Users/User.hpp>

#include <tuple>

namespace Tanker::Users
{
User::User(Trustchain::UserId const& userId,
           std::optional<Crypto::PublicEncryptionKey> const& userKey,
           gsl::span<Device const> devices)
  : _id(userId), _userKey(userKey), _devices(devices.begin(), devices.end())
{
}

void User::addDevice(Device const& device)
{
  _devices.push_back(device);
}

void User::setUserKey(Crypto::PublicEncryptionKey const& userKey)
{
  _userKey = userKey;
}

std::optional<Device> User::findDevice(
    Trustchain::DeviceId const& deviceId) const
{
  for (auto const& device : _devices)
    if (device.id() == deviceId)
      return device;
  return std::nullopt;
}

Device& User::getDevice(Trustchain::DeviceId const& deviceId)
{
  for (auto& device : _devices)
    if (device.id() == deviceId)
      return device;
  throw Errors::AssertionError("did not find user's device");
}

std::optional<Device> User::findDevice(
    Crypto::PublicEncryptionKey const& publicKey) const
{
  for (auto const& device : _devices)
    if (device.publicEncryptionKey() == publicKey)
      return device;
  return std::nullopt;
}

Trustchain::UserId const& User::id() const
{
  return _id;
}

std::optional<Crypto::PublicEncryptionKey> const& User::userKey() const
{
  return _userKey;
}

std::vector<Device> const& User::devices() const
{
  return _devices;
}

bool operator==(User const& l, User const& r)
{
  return std::tie(l.id(), l.userKey(), l.devices()) ==
         std::tie(r.id(), r.userKey(), r.devices());
}

bool operator!=(User const& l, User const& r)
{
  return !(l == r);
}
bool operator<(User const& l, User const& r)
{
  return l.id() < r.id();
}
}
