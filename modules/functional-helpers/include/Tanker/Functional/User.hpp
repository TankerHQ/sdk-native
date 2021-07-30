#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Functional/Device.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <optional>
#include <string>

namespace Tanker
{
namespace Functional
{
class User
{
public:
  std::string trustchainUrl;
  std::string trustchainId;
  std::string identity;

  User() = default;

  User(std::string trustchainUrl,
       std::string trustchainId,
       std::string trustchainPrivateSignatureKey);

  Device makeDevice();

  tc::cotask<std::vector<Device>> makeDevices(std::size_t nb);

  SPublicIdentity spublicIdentity() const;
};

void to_json(nlohmann::json& j, User const& state);
void from_json(nlohmann::json const& j, User& state);
}
}
