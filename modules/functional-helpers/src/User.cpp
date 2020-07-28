#include <Tanker/Functional/User.hpp>
#include <Tanker/Identity/Extract.hpp>
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
  auto userId = Tanker::Trustchain::UserId{};
  Crypto::randomFill(userId.base());
  return userId;
}
}

User::User(std::string trustchainUrl,
           std::string trustchainId,
           std::string trustchainPrivateSignatureKey)
  : trustchainUrl(std::move(trustchainUrl)),
    trustchainId(std::move(trustchainId)),
    userId(createRandomUserId()),
    identity(Identity::createIdentity(
        mgs::base64::decode<Trustchain::TrustchainId>(this->trustchainId),
        mgs::base64::decode<Crypto::PrivateSignatureKey>(
            trustchainPrivateSignatureKey),
        this->userId)),
    userToken(std::nullopt)
{
}

void User::reuseCache()
{
  _currentDevice = 0;
}

Device User::makeDevice(DeviceType type)
{
  if (type == DeviceType::New)
    return Device(trustchainUrl, trustchainId, suserId(), sidentity());

  if (_currentDevice == _cachedDevices->size())
    _cachedDevices->push_back(
        Device(trustchainUrl, trustchainId, suserId(), sidentity()));
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

std::string User::sidentity() const
{
  return to_string(identity);
}

SPublicIdentity User::spublicIdentity() const
{
  return SPublicIdentity{to_string(Identity::getPublicIdentity(identity))};
}

void to_json(nlohmann::json& j, User const& user)
{
  j["suser_id"] = user.suserId();
  j["identity"] = user.sidentity();
}

void from_json(nlohmann::json const& j, User& user)
{
  user.userId = mgs::base64::decode<Tanker::Trustchain::UserId>(
      j.at("suser_id").get<std::string>());
  if (j.find("user_token") != j.end())
    user.userToken = j.at("user_token").get<std::string>();
  else if (j.find("identity") != j.end())
  {
    user.identity =
        nlohmann::json::parse(
            mgs::base64::decode(j.at("identity").get<std::string>()))
            .get<Identity::SecretPermanentIdentity>();
  }
  else
    throw std::runtime_error("missing User identity field");
}
}
}
