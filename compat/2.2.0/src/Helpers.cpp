#include <Compat/Helpers.hpp>

#include <Helpers/Buffers.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Version.hpp>

using Tanker::Functional::TrustchainFactory;
using Tanker::Functional::User;
using Tanker::Trustchain::TrustchainId;

CorePtr createCore(std::string const& url,
                   Tanker::Trustchain::TrustchainId const& id,
                   std::string const& tankerPath)
{
  return std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>(
      new Tanker::AsyncCore(
          url,
          Tanker::Network::SdkInfo{"test", id, TANKER_VERSION},
          tankerPath),
      AsyncCoreDeleter{});
}

UserSession signUpUser(Tanker::Functional::Trustchain& trustchain,
                       std::string const& tankerPath)
{
  auto user = trustchain.makeUser();
  auto core = createCore(trustchain.url, trustchain.id, tankerPath);
  core->start(user.identity).get();
  core->registerIdentity(Tanker::Passphrase{"my password"}).get();
  return {std::move(core), std::move(user)};
}

void claim(CorePtr& core,
           Tanker::Functional::Trustchain& trustchain,
           Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
           std::string const& semail,
           std::string const& verifCode)
{
  auto const email = Tanker::Email{semail};
  core->attachProvisionalIdentity(provisionalIdentity).get();
  core
      ->verifyProvisionalIdentity(Tanker::Unlock::EmailVerification{
          email, Tanker::VerificationCode{verifCode}})
      .get();
}

UserSession signUpAndClaim(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    std::string const& verifCode,
    Tanker::Functional::Trustchain& trustchain,
    std::string const& tankerPath)
{
  auto session = signUpUser(trustchain, tankerPath);
  claim(session.core, trustchain, provisionalIdentity, email, verifCode);
  return session;
}

CorePtr signInUser(std::string const& identity,
                   Tanker::Functional::Trustchain& trustchain,
                   std::string const& tankerPath)
{
  auto core = createCore(trustchain.url, trustchain.id, tankerPath);
  core->start(identity).get();
  return core;
}

void decrypt(CorePtr const& core,
             std::vector<uint8_t> const& encryptedData,
             std::string const& expectedData)
{
  auto decryptedData = std::vector<uint8_t>(
      Tanker::AsyncCore::decryptedSize(encryptedData).get());
  core->decrypt(decryptedData.data(), encryptedData).get();
  fmt::print(">> {}\n",
             std::string(decryptedData.begin(), decryptedData.end()));
  if (std::string(decryptedData.begin(), decryptedData.end()) != expectedData)
    throw std::runtime_error("failed to decrypt");
}

std::vector<uint8_t> encrypt(CorePtr& core,
                             std::string clearData,
                             std::vector<Tanker::SPublicIdentity> users,
                             std::vector<Tanker::SGroupId> groups)
{
  auto const buffer = Tanker::make_buffer(clearData);
  auto encryptedData =
      std::vector<uint8_t>(Tanker::AsyncCore::encryptedSize(clearData.size()));

  core->encrypt(encryptedData.data(), buffer, users, groups).get();
  return encryptedData;
}

User upgradeToIdentity(Tanker::Trustchain::TrustchainId const& trustchainId,
                       User user)
{
  if (user.userToken)
  {
    user.identity = Tanker::Identity::upgradeUserToken(
        cppcodec::base64_rfc4648::encode(trustchainId),
        user.suserId,
        user.userToken.value());
    user.userToken.reset();
  }
  return user;
}
