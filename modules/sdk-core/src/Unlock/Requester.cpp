#include <Tanker/Unlock/Requester.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/HttpClient.hpp>

#include <mgs/base64url.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <optional>

namespace Tanker::Unlock
{
Requester::Requester(HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::optional<Crypto::PublicEncryptionKey>> Requester::userStatus(
    Trustchain::UserId const& userId)
{
  using namespace fmt::literals;
  auto res = TC_AWAIT(_httpClient->asyncGet(
      fmt::format("users/{userId:#S}", "userId"_a = userId)));
  if (res.has_error() && res.error().ec == Errors::AppdErrc::UserNotFound)
    TC_RETURN(std::nullopt);

  TC_RETURN(mgs::base64url_nopad::decode<Crypto::PublicEncryptionKey>(
      res.value().at("user").at("public_encryption_key").get<std::string>()));
}

tc::cotask<void> Requester::setVerificationMethod(
    Trustchain::UserId const& userId, Unlock::Request const& request)
{
  nlohmann::json payload{{"verification", request}};
  auto const target = fmt::format("users/{userId:#S}/verification-methods",
                                  fmt::arg("userId", userId));
  TC_AWAIT(_httpClient->asyncPost(target, std::move(payload))).value();
}

tc::cotask<std::vector<std::uint8_t>> Requester::fetchVerificationKey(
    Trustchain::UserId const& userId, Unlock::Request const& request)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncPost(
      fmt::format("users/{userId:#S}/verification-key", "userId"_a = userId),
      {{"verification", request}}));
  TC_RETURN(mgs::base64url_nopad::decode<std::vector<uint8_t>>(
      res.value().at("encrypted_verification_key").get<std::string>()));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Requester::fetchVerificationMethods(Trustchain::UserId const& userId)
{
  using namespace fmt::literals;
  auto const res = TC_AWAIT(_httpClient->asyncGet(fmt::format(
      "users/{userId:#S}/verification-methods", "userId"_a = userId)));
  TC_RETURN(res.value()
                .at("verification_methods")
                .get<std::vector<Unlock::VerificationMethod>>());
}

tc::cotask<void> Requester::createUser(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    gsl::span<uint8_t const> userCreation,
    gsl::span<uint8_t const> firstDevice,
    Unlock::Request const& verificationRequest,
    gsl::span<uint8_t const> encryptedVerificationKey)
{
  nlohmann::json body{
      {"app_id", trustchainId},
      {"user_id", userId},
      {"ghost_device_creation", mgs::base64::encode(userCreation)},
      {"first_device_creation", mgs::base64::encode(firstDevice)},
      {"encrypted_verification_key",
       mgs::base64::encode(encryptedVerificationKey)},
      {"verification", verificationRequest},
  };
  auto const target =
      fmt::format("users/{userId:#S}", fmt::arg("userId", userId));

  auto const res = TC_AWAIT(_httpClient->asyncPost(target, std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}

tc::cotask<void> Requester::createDevice(
    gsl::span<uint8_t const> deviceCreation)
{
  nlohmann::json body{{"device_creation", mgs::base64::encode(deviceCreation)}};

  auto const res = TC_AWAIT(_httpClient->asyncPost("devices", std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}
}
