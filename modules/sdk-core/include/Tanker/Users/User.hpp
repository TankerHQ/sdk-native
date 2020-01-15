#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <optional>
#include <vector>

namespace Tanker::Users
{
struct User
{
  std::optional<Device> findDevice(Trustchain::DeviceId const& deviceId) const;
  Device& getDevice(Trustchain::DeviceId const& deviceId);
  std::optional<Device> findDevice(
      Crypto::PublicEncryptionKey const& publicKey) const;

  Trustchain::UserId id;
  std::optional<Crypto::PublicEncryptionKey> userKey;
  std::vector<Device> devices;
};

bool operator==(User const& l, User const& r);
bool operator!=(User const& l, User const& r);
bool operator<(User const& l, User const& r);
}
