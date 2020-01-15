#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Users/User.hpp>

#include <tuple>

namespace Tanker::Users
{
std::optional<Device> User::findDevice(
    Trustchain::DeviceId const& deviceId) const
{
  for (auto const& device : devices)
    if (device.id == deviceId)
      return device;
  return std::nullopt;
}

Device& User::getDevice(Trustchain::DeviceId const& deviceId)
{
  for (auto& device : devices)
    if (device.id == deviceId)
      return device;
  throw Errors::AssertionError("did not find user's device");
}

std::optional<Device> User::findDevice(
    Crypto::PublicEncryptionKey const& publicKey) const
{
  for (auto const& device : devices)
    if (device.publicEncryptionKey == publicKey)
      return device;
  return std::nullopt;
}

bool operator==(User const& l, User const& r)
{
  return std::tie(l.id, l.userKey, l.devices) ==
         std::tie(r.id, r.userKey, r.devices);
}
bool operator!=(User const& l, User const& r)
{
  return !(l == r);
}
bool operator<(User const& l, User const& r)
{
  return l.id < r.id;
}
}
