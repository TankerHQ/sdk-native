#include <Tanker/Unlock/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/HttpClient.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::Unlock
{
static void from_json(nlohmann::json const& j, UserStatusResult& result)
{
  j.at("device_exists").get_to(result.deviceExists);
  result.userExists = j.at("user_exists").get<bool>();
  auto const lastReset = j.at("last_reset").get<std::string>();
  if (!lastReset.empty())
    result.lastReset = mgs::base64::decode<Crypto::Hash>(lastReset);
  else
    result.lastReset = Crypto::Hash{};
}

Requester::Requester(Client* client, HttpClient* httpClient)
  : _client(client), _httpClient(httpClient)
{
}

tc::cotask<UserStatusResult> Requester::userStatus(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Crypto::PublicSignatureKey const& publicSignatureKey)
{
  nlohmann::json request{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"device_public_signature_key", publicSignatureKey},
  };

  auto const reply = TC_AWAIT(_client->emit("get user status", request));

  TC_RETURN(reply.get<UserStatusResult>());
}

tc::cotask<void> Requester::setVerificationMethod(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{{"verification", request}};
  auto const target = fmt::format("users/{userId:#S}/verification-methods",
                                  fmt::arg("userId", userId));
  TC_AWAIT(_httpClient->asyncPost(target, std::move(payload))).value();
  TC_RETURN();
}

tc::cotask<std::vector<std::uint8_t>> Requester::fetchVerificationKey(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification", request},
  };
  auto const response =
      TC_AWAIT(_client->emit("get verification key", payload));
  TC_RETURN(mgs::base64::decode<std::vector<uint8_t>>(
      response.at("encrypted_verification_key").get<std::string>()));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Requester::fetchVerificationMethods(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId)
{
  auto const request =
      nlohmann::json{{"trustchain_id", trustchainId}, {"user_id", userId}};

  auto const reply =
      TC_AWAIT(_client->emit("get verification methods", request));
  auto methods = reply.at("verification_methods")
                     .get<std::vector<Unlock::VerificationMethod>>();
  TC_RETURN(methods);
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
    Trustchain::TrustchainId const& trustchainId,
    gsl::span<uint8_t const> deviceCreation)
{
  nlohmann::json body{{"device_creation", mgs::base64::encode(deviceCreation)}};

  auto const res = TC_AWAIT(_httpClient->asyncPost("devices", std::move(body)));
  auto accessToken = res.value().at("access_token").get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}
}
