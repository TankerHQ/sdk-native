#pragma once

#include <Tanker/Test/Functional/Device.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <string>

namespace Tanker
{
namespace Test
{
enum class DeviceType
{
  Cached,
  New,
};

class User
{
public:
  User(std::string trustchainUrl,
       std::string trustchainId,
       std::string trustchainPrivateSignatureKey);

  void reuseCache();

  Device makeDevice(DeviceType type = DeviceType::Cached);

  tc::cotask<std::vector<Device>> makeDevices(std::size_t nb);

  SUserId suserId() const
  {
    return _userId;
  }

  std::string identity() const
  {
    return _identity;
  }

  SPublicIdentity spublicIdentity() const;

private:
  std::string _trustchainUrl;
  std::string _trustchainId;
  SUserId _userId;
  std::string _identity;

  unsigned int _currentDevice = 0;
  std::shared_ptr<std::vector<Device>> _cachedDevices =
      std::make_shared<std::vector<Device>>();
};
}
}
