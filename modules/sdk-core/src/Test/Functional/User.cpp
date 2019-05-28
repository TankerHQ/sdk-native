#include <Tanker/AsyncCore.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Test/Functional/User.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Test
{
namespace
{
auto createRandomUserId()
{
  auto rdm = std::array<std::uint8_t, 10>{};
  Crypto::randomFill(rdm);
  return Tanker::SUserId{cppcodec::base64_rfc4648::encode(rdm)};
}
}

User::User(std::string trustchainUrl,
           std::string trustchainId,
           std::string trustchainPrivateSignatureKey)
  : trustchainUrl(std::move(trustchainUrl)),
    trustchainId(std::move(trustchainId)),
    suserId(createRandomUserId()),
    identity(Identity::createIdentity(
        this->trustchainId, trustchainPrivateSignatureKey, suserId)),
    userToken(nonstd::nullopt)
{
}

void User::reuseCache()
{
  _currentDevice = 0;
}

Device User::makeDevice(DeviceType type)
{
  if (type == DeviceType::New)
    return Device(trustchainUrl, trustchainId, suserId, identity);

  if (_currentDevice == _cachedDevices->size())
    _cachedDevices->push_back(
        Device(trustchainUrl, trustchainId, suserId, identity));
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
    TC_AWAIT(device->attachDevice(*session));
  TC_RETURN(devices);
}

SPublicIdentity User::spublicIdentity() const
{
  return SPublicIdentity{Identity::getPublicIdentity(identity)};
}

void to_json(nlohmann::json& j, User const& user)
{
  j["suser_id"] = user.suserId;
  j["identity"] = user.identity;
}

void from_json(nlohmann::json const& j, User& user)
{
  j.at("suser_id").get_to(user.suserId);
  if (j.find("user_token") != j.end())
    user.userToken = j.at("user_token").get<std::string>();
  else if (j.find("identity") != j.end())
    j.at("identity").get_to(user.identity);
  else
    throw std::runtime_error("missing User identity field");
}
}
}
