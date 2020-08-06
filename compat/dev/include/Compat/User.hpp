#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Functional/Device.hpp>
#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <optional>
#include <string>

enum class DeviceType
{
  Cached,
  New,
};

namespace Tanker::Functional
{
  struct Trustchain;
}

class User
{
public:
  std::string trustchainUrl;
  std::string trustchainId;
  Tanker::SUserId suserId;
  std::string identity;
  std::optional<std::string> userToken;

  User() = default;

  User(std::string trustchainUrl,
       std::string trustchainId,
       std::string trustchainPrivateSignatureKey);

  void reuseCache();

  Tanker::Functional::Device makeDevice(DeviceType type = DeviceType::Cached);

  tc::cotask<std::vector<Tanker::Functional::Device>> makeDevices(std::size_t nb);

  Tanker::SPublicIdentity spublicIdentity() const;

private:
  unsigned int _currentDevice = 0;
  std::shared_ptr<std::vector<Tanker::Functional::Device>> _cachedDevices =
      std::make_shared<std::vector<Tanker::Functional::Device>>();
};

User makeUser(Tanker::Functional::Trustchain const &tr);

void to_json(nlohmann::json& j, User const& state);
void from_json(nlohmann::json const& j, User& state);
