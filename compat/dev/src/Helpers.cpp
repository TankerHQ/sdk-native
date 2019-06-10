#include <Compat/Helpers.hpp>

#include <Helpers/Buffers.hpp>
#include <Tanker/Test/Functional/TrustchainFactory.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Version.hpp>

using Tanker::Test::TrustchainFactory;
using Tanker::Test::User;
using Tanker::Trustchain::TrustchainId;

namespace
{
tc::future<Tanker::VerificationCode> getVerificationCode(
    TrustchainId const& id, Tanker::Email const& email)
{
  return tc::async_resumable([=]() -> tc::cotask<Tanker::VerificationCode> {
    auto tf = TC_AWAIT(TrustchainFactory::create());
    TC_RETURN(TC_AWAIT(tf->getVerificationCode(id, email)));
  });
}
}

CorePtr createCore(std::string const& url,
                   Tanker::Trustchain::TrustchainId const& id,
                   std::string const& tankerPath)
{
  return std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>(
      new Tanker::AsyncCore(
          url, Tanker::SdkInfo{"test", id, TANKER_VERSION}, tankerPath),
      AsyncCoreDeleter{});
}

UserSession signUpUser(Tanker::Test::Trustchain& trustchain,
                       std::string const& tankerPath)
{
  auto user = trustchain.makeUser();
  auto core = createCore(trustchain.url, trustchain.id, tankerPath);
  core->start(user.identity).get();
  core->registerIdentity(Tanker::Password{"my password"}).get();
  return {std::move(core), std::move(user)};
}

void claim(CorePtr& core,
           Tanker::Test::Trustchain& trustchain,
           Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
           std::string const& semail)
{
  auto const email = Tanker::Email{semail};
  auto const verifCode = getVerificationCode(trustchain.id, email).get();
  core->attachProvisionalIdentity(provisionalIdentity).get();
  core->verifyProvisionalIdentity(
          Tanker::Unlock::EmailVerification{email, verifCode})
      .get();
}

UserSession signUpAndClaim(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    Tanker::Test::Trustchain& trustchain,
    std::string const& tankerPath)
{
  auto session = signUpUser(trustchain, tankerPath);
  claim(session.core, trustchain, provisionalIdentity, email);
  return session;
}

CorePtr signInUser(std::string const& identity,
                   Tanker::Test::Trustchain& trustchain,
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
