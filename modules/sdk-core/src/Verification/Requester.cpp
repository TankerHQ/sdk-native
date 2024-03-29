#include <Tanker/Verification/Requester.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Network/HttpClient.hpp>

#include <mgs/base64.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <optional>

namespace Tanker::Verification
{
Requester::Requester(Network::HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::optional<Crypto::PublicEncryptionKey>> Requester::userStatus(Trustchain::UserId const& userId)
{
  using namespace fmt::literals;
  auto res = TC_AWAIT(
      _httpClient->asyncUnauthGet(_httpClient->makeUrl(fmt::format("users/{userId:#S}", "userId"_a = userId))));
  if (res.has_error() && res.error().ec == Errors::AppdErrc::UserNotFound)
    TC_RETURN(std::nullopt);

  TC_RETURN(res.value().at("user").at("public_encryption_key").get<Crypto::PublicEncryptionKey>());
}

tc::cotask<void> Requester::setVerificationMethod(Trustchain::UserId const& userId,
                                                  SetVerifMethodRequest const& request)
{
  auto const target =
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/verification-methods", fmt::arg("userId", userId)));
  TC_AWAIT(_httpClient->asyncPost(target, request)).value();
}

tc::cotask<std::vector<std::uint8_t>> Requester::fetchVerificationKey(Trustchain::UserId const& userId,
                                                                      RequestWithVerif const& request)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/verification-key", "userId"_a = userId)),
      {{"verification", request}}));
  TC_RETURN(mgs::base64::decode<std::vector<std::uint8_t>>(
      res.value().at("encrypted_verification_key_for_user_secret").get<std::string>()));
}

tc::cotask<std::vector<std::uint8_t>> Requester::fetchE2eVerificationKey(Trustchain::UserId const& userId,
                                                                         RequestWithVerif const& request)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/verification-key", "userId"_a = userId)),
      {{"verification", request}}));
  TC_RETURN(mgs::base64::decode<std::vector<std::uint8_t>>(
      res.value().at("encrypted_verification_key_for_e2e_passphrase").get<std::string>()));
}

tc::cotask<boost::variant2::variant<EncryptedVerificationKeyForUserKey, EncryptedVerificationKeyForUserSecret>>
Requester::fetchEncryptedVerificationKey(Trustchain::UserId const& userId)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncGet(_httpClient->makeUrl("encrypted-verification-key")));

  if (auto vkForUs = res.value().at("encrypted_verification_key_for_user_secret"); !vkForUs.is_null())
    TC_RETURN(mgs::base64::decode<EncryptedVerificationKeyForUserSecret>(vkForUs.get<std::string>()));
  else
  {
    auto vkForUk = res.value().at("encrypted_verification_key_for_user_key").get<std::string>();
    TC_RETURN(mgs::base64::decode<EncryptedVerificationKeyForUserKey>(vkForUk));
  }
}

tc::cotask<std::vector<boost::variant2::variant<VerificationMethod, EncryptedVerificationMethod>>>
Requester::fetchVerificationMethods(Trustchain::UserId const& userId)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncUnauthGet(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/verification-methods", "userId"_a = userId))));
  auto value = res.value()
                   .at("verification_methods")
                   .get<std::vector<boost::variant2::variant<VerificationMethod, EncryptedVerificationMethod>>>();
  TC_RETURN(value);
}

tc::cotask<Oidc::Challenge> Requester::getOidcChallenge(Trustchain::UserId const& userId, Oidc::Nonce const& nonce)
{
  using namespace fmt::literals;
  nlohmann::json body{{"nonce", nonce}};
  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/oidc/challenges", "userId"_a = userId)), std::move(body)));
  TC_RETURN(res.value().at("challenge").get<Oidc::Challenge>());
}

tc::cotask<std::string> Requester::getSessionToken(Trustchain::UserId const& userId,
                                                   gsl::span<uint8_t const> sessionCertificate,
                                                   std::string nonce)
{
  using namespace fmt::literals;
  nlohmann::json body{{"session_certificate", mgs::base64::encode(sessionCertificate)}, {"nonce", nonce}};

  auto const res = TC_AWAIT(_httpClient->asyncPost(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/session-certificates", "userId"_a = userId)),
      std::move(body)));

  TC_RETURN(res.value().at("session_token").get<std::string>());
}

tc::cotask<void> Requester::createUser(Trustchain::TrustchainId const& trustchainId,
                                       Trustchain::UserId const& userId,
                                       gsl::span<uint8_t const> userCreation,
                                       gsl::span<uint8_t const> firstDevice,
                                       RequestWithVerif const& verificationRequest,
                                       gsl::span<uint8_t const> encryptedVerificationKeyForUserSecret)
{
  nlohmann::json body{
      {"app_id", trustchainId},
      {"user_id", userId},
      {"ghost_device_creation", mgs::base64::encode(userCreation)},
      {"first_device_creation", mgs::base64::encode(firstDevice)},
      {"v2_encrypted_verification_key", mgs::base64::encode(encryptedVerificationKeyForUserSecret)},
      {"verification", verificationRequest},
  };
  auto const target = _httpClient->makeUrl(fmt::format("users/{userId:#S}", fmt::arg("userId", userId)));

  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(target, std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}

tc::cotask<void> Requester::createUserE2e(Trustchain::TrustchainId const& trustchainId,
                                          Trustchain::UserId const& userId,
                                          gsl::span<uint8_t const> userCreation,
                                          gsl::span<uint8_t const> firstDevice,
                                          RequestWithVerif const& verificationRequest,
                                          gsl::span<uint8_t const> encryptedVerificationKeyForE2ePassphrase,
                                          gsl::span<uint8_t const> encryptedVerificationKeyForUserKey)
{
  nlohmann::json body{
      {"app_id", trustchainId},
      {"user_id", userId},
      {"ghost_device_creation", mgs::base64::encode(userCreation)},
      {"first_device_creation", mgs::base64::encode(firstDevice)},
      {"encrypted_verification_key_for_e2e_passphrase", mgs::base64::encode(encryptedVerificationKeyForE2ePassphrase)},
      {"encrypted_verification_key_for_user_key", mgs::base64::encode(encryptedVerificationKeyForUserKey)},
      {"verification", verificationRequest},
  };
  auto const target = _httpClient->makeUrl(fmt::format("users/{userId:#S}", fmt::arg("userId", userId)));

  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(target, std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}

tc::cotask<void> Requester::enrollUser(Trustchain::TrustchainId const& trustchainId,
                                       Trustchain::UserId const& userId,
                                       gsl::span<uint8_t const> userCreation,
                                       gsl::span<RequestWithVerif const> verificationRequests,
                                       gsl::span<uint8_t const> encryptedVerificationKey)
{
  nlohmann::json body{
      {"app_id", trustchainId},
      {"user_id", userId},
      {"ghost_device_creation", mgs::base64::encode(userCreation)},
      {"encrypted_verification_key", mgs::base64::encode(encryptedVerificationKey)},
      {"verifications", verificationRequests},
  };
  auto const target = _httpClient->makeUrl(fmt::format("users/{userId:#S}/enroll", fmt::arg("userId", userId)));

  TC_AWAIT(_httpClient->asyncUnauthPost(target, std::move(body))).value();
}

tc::cotask<void> Requester::createDevice(gsl::span<uint8_t const> deviceCreation)
{
  nlohmann::json body{{"device_creation", mgs::base64::encode(deviceCreation)}};

  auto const res = TC_AWAIT(_httpClient->asyncUnauthPost(_httpClient->makeUrl("devices"), std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}
}
