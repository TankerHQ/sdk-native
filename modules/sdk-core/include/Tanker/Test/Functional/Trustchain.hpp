#pragma once

#include <Tanker/Test/Functional/User.hpp>

#include <Tanker/Admin.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <Helpers/Config.hpp>

#include <optional.hpp>

#include <string>

namespace Tanker
{
namespace Test
{
enum class UserType
{
  Cached,
  New,
};

class Trustchain
{
public:
  Trustchain();

  tc::cotask<void> init();
  tc::cotask<void> destroy();

  void reuseCache();

  User makeUser(UserType = UserType::Cached);

  auto const& url() const
  {
    return this->_trustchainUrl;
  }

  auto const& id() const
  {
    return this->_trustchainId;
  }

  auto const& signatureKeys() const
  {
    return this->_trustchainSignatureKeyPair;
  }

  tc::cotask<VerificationCode> getVerificationCode(Email const& email);

  static Trustchain& getInstance();

private:
  std::string _trustchainUrl;
  std::string _trustchainName;
  TrustchainId _trustchainId;
  Admin _admin;
  Crypto::SignatureKeyPair _trustchainSignatureKeyPair;

  uint32_t _currentUser = 0;
  std::vector<User> _cachedUsers;
};
}
}
