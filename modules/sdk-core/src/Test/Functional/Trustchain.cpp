#include <Tanker/Test/Functional/Trustchain.hpp>

#include <Tanker/AConnection.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>

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
    _admin(makeConnection(_trustchainUrl), Tanker::TestConstants::idToken()),
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
  auto const trustchainIdString = base64::encode(_trustchainId);
  auto const trustchainPrivateKeyString =
      base64::encode(_trustchainSignatureKeyPair.privateKey);

  if (type == UserType::New)
    return User(_trustchainUrl, trustchainIdString, trustchainPrivateKeyString);

  if (_currentUser == _cachedUsers.size())
    _cachedUsers.push_back(
        User(_trustchainUrl, trustchainIdString, trustchainPrivateKeyString));
  return _cachedUsers[_currentUser++];
}

tc::cotask<VerificationCode> Trustchain::getVerificationCode(
    SUserId const& userId, Email const& email)
{
  TC_RETURN(TC_AWAIT(this->_admin.getVerificationCode(
      this->id(), obfuscateUserId(userId, this->id()), email)));
}

Trustchain& Trustchain::getInstance()
{
  static Trustchain instance;
  instance.reuseCache();
  return instance;
}
}
}
