#include <Compat/User.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Functional/Trustchain.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

namespace
{
auto createRandomUserId()
{
  auto rdm = std::array<std::uint8_t, 10>{};
  Tanker::Crypto::randomFill(rdm);
  return Tanker::SUserId{mgs::base64::encode(rdm)};
}
}

User::User(std::string trustchainUrl,
           std::string trustchainId,
           std::string trustchainPrivateSignatureKey)
  : trustchainUrl(std::move(trustchainUrl)),
    trustchainId(std::move(trustchainId)),
    suserId(createRandomUserId()),
    identity(Tanker::Identity::createIdentity(
        this->trustchainId, trustchainPrivateSignatureKey, suserId)),
    userToken(std::nullopt)
{
}

User makeUser(Tanker::Functional::Trustchain const &trustchain)
{
  auto const trustchainIdString = mgs::base64::encode(trustchain.id);
  auto const trustchainPrivateKeyString =
      mgs::base64::encode(trustchain.keyPair.privateKey);

  return User(trustchain.url, trustchainIdString, trustchainPrivateKeyString);
}

void User::reuseCache()
{
  _currentDevice = 0;
}

using Tanker::Functional::Device;

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
    TC_AWAIT(device->open());
  TC_RETURN(devices);
}

Tanker::SPublicIdentity User::spublicIdentity() const
{
  return Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(identity)};
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
