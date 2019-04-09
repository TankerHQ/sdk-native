#include <Tanker/AsyncCore.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Test/Functional/User.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Test
{

User::User(std::string trustchainUrl,
           std::string trustchainId,
           std::string trustchainPrivateSignatureKey)
  : _trustchainUrl(std::move(trustchainUrl)),
    _trustchainId(std::move(trustchainId))
{
  Crypto::Hash buf;
  Crypto::randomFill(buf);
  _userId = SUserId{
      cppcodec::base64_rfc4648::encode(gsl::make_span(buf).subspan(0, 8))};
  _identity = Identity::createIdentity(
      _trustchainId, trustchainPrivateSignatureKey, _userId);
}

void User::reuseCache()
{
  _currentDevice = 0;
}

Device User::makeDevice(DeviceType type)
{
  if (type == DeviceType::New)
    return Device(_trustchainUrl, _trustchainId, _userId, _identity);

  if (_currentDevice == _cachedDevices->size())
    _cachedDevices->push_back(
        Device(_trustchainUrl, _trustchainId, _userId, _identity));
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
  return SPublicIdentity{Identity::getPublicIdentity(_identity)};
}
}
}
