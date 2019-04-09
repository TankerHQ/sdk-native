#pragma once

#include <Tanker/Test/Functional/Device.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <optional.hpp>
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
  std::string trustchainUrl;
  std::string trustchainId;
  SUserId suserId;
  std::string identity;
  nonstd::optional<std::string> userToken;

  User() = default;

  User(std::string trustchainUrl,
       std::string trustchainId,
       std::string trustchainPrivateSignatureKey);

  void reuseCache();

  Device makeDevice(DeviceType type = DeviceType::Cached);

  tc::cotask<std::vector<Device>> makeDevices(std::size_t nb);

  SPublicIdentity spublicIdentity() const;

private:
  unsigned int _currentDevice = 0;
  std::shared_ptr<std::vector<Device>> _cachedDevices =
      std::make_shared<std::vector<Device>>();
};

void to_json(nlohmann::json& j, User const& state);
void from_json(nlohmann::json const& j, User& state);
}
}
