#include <Tanker/Test/Functional/Trustchain.hpp>

#include <Tanker/ConnectionFactory.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <tconcurrent/coroutine.hpp>

#include <Helpers/Config.hpp>

#include <memory>
#include <string>
#include <utility>

namespace Tanker
{
namespace Test
{
Trustchain::Trustchain()
  : _trustchainUrl(Tanker::TestConstants::trustchainUrl()),
    _admin(ConnectionFactory::create(_trustchainUrl, nonstd::nullopt),
           Tanker::TestConstants::idToken()),
    _trustchainSignatureKeyPair(Crypto::makeSignatureKeyPair())
{
}

tc::cotask<void> Trustchain::init()
{
  TC_AWAIT(_admin.start());
  _trustchainId = TC_AWAIT(_admin.createTrustchain(
      "functest-cpp", _trustchainSignatureKeyPair, true));
}

tc::cotask<void> Trustchain::destroy()
{
  TC_AWAIT(_admin.deleteTrustchain(_trustchainId));
  _cachedUsers.clear();
  _currentUser = 0;
}

void Trustchain::reuseCache()
{
  for (auto& user : _cachedUsers)
    user.reuseCache();
  _currentUser = 0;
}

User Trustchain::makeUser(UserType type)
{
  auto const trustchainIdString =
      cppcodec::base64_rfc4648::encode(_trustchainId);
  auto const trustchainPrivateKeyString =
      cppcodec::base64_rfc4648::encode(_trustchainSignatureKeyPair.privateKey);

  if (type == UserType::New)
    return User(_trustchainUrl, trustchainIdString, trustchainPrivateKeyString);

  if (_currentUser == _cachedUsers.size())
    _cachedUsers.push_back(
        User(_trustchainUrl, trustchainIdString, trustchainPrivateKeyString));
  return _cachedUsers[_currentUser++];
}

tc::cotask<VerificationCode> Trustchain::getVerificationCode(Email const& email)
{
  TC_RETURN(TC_AWAIT(this->_admin.getVerificationCode(
      this->id(), email)));
}

Trustchain& Trustchain::getInstance()
{
  static Trustchain instance;
  instance.reuseCache();
  return instance;
}
}
}
