#include <Tanker/AsyncCore.hpp>

#include <Tanker/Functional/User.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Functional
{
namespace
{
auto createRandomUserId()
{
  auto rdm = std::array<std::uint8_t, 10>{};
  Crypto::randomFill(rdm);
  return SUserId{mgs::base64::encode(rdm)};
}
}

User::User(std::string trustchainUrl,
           std::string trustchainId,
           std::string trustchainPrivateSignatureKey)
  : trustchainUrl(std::move(trustchainUrl)),
    trustchainId(std::move(trustchainId)),
    identity(Identity::createIdentity(this->trustchainId,
                                      trustchainPrivateSignatureKey,
                                      createRandomUserId()))
{
}

void User::reuseCache()
{
  _currentDevice = 0;
}

Device User::makeDevice(DeviceType type)
{
  if (type == DeviceType::New)
    return Device(trustchainUrl, trustchainId, identity);

  if (_currentDevice == _cachedDevices->size())
    _cachedDevices->push_back(Device(trustchainUrl, trustchainId, identity));
  return (*_cachedDevices)[_currentDevice++];
}

tc::cotask<std::vector<Device>> User::makeDevices(std::size_t nb)
{
  std::vector<Device> devices;
  devices.reserve(nb);
  std::generate_n(
      std::back_inserter(devices), nb, [&] { return makeDevice(); });
  auto session = TC_AWAIT(devices.front().open());
  for (auto device = ++devices.begin(); device != devices.end(); ++device)
    TC_AWAIT(device->open());
  TC_RETURN(devices);
}

SPublicIdentity User::spublicIdentity() const
{
  return SPublicIdentity{Identity::getPublicIdentity(identity)};
}

void to_json(nlohmann::json& j, User const& user)
{
  j["identity"] = user.identity;
}

void from_json(nlohmann::json const& j, User& user)
{
  if (j.find("identity") != j.end())
    j.at("identity").get_to(user.identity);
  else
    throw std::runtime_error("missing User identity field");
}
}
}
