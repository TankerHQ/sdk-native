
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrcCategory.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <fmt/format.h>
#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Users
{
namespace
{
template <typename T>
Crypto::Hash hashField(T const& field)
{
  return Crypto::generichash(
      gsl::make_span(field).template as_span<std::uint8_t const>());
}

std::vector<Trustchain::UserAction> fromBlocksToUserActions(
    gsl::span<const std::string> const& blocks)
{
  std::vector<Trustchain::UserAction> entries;
  entries.reserve(blocks.size());
  std::transform(
      std::begin(blocks),
      std::end(blocks),
      std::back_inserter(entries),
      [](auto const& block) {
        return Trustchain::deserializeUserAction(mgs::base64::decode(block));
      });

  return entries;
}

std::vector<Trustchain::KeyPublishAction> fromBlocksToKeyPublishActions(
    gsl::span<const std::string> const& blocks)
{
  std::vector<Trustchain::KeyPublishAction> entries;
  entries.reserve(blocks.size());
  std::transform(std::begin(blocks),
                 std::end(blocks),
                 std::back_inserter(entries),
                 [](auto const& block) {
                   return Trustchain::deserializeKeyPublishAction(
                       mgs::base64::decode(block));
                 });

  return entries;
}
}

Requester::Requester(Client* client, HttpClient* httpClient)
  : _client(client), _httpClient(httpClient)
{
}

tc::cotask<Requester::GetMeResult> Requester::getMe()
{
  auto const response = TC_AWAIT(_client->emit("get my user blocks", {}));
  auto const blocks = response.get<std::vector<std::string>>();
  if (blocks.empty())
    throw formatEx(Errors::Errc::InternalError,
                   "received too few blocks for \"get my user blocks\"");
  auto const trustchainCreation =
      Serialization::deserialize<Trustchain::Actions::TrustchainCreation>(
          mgs::base64::decode(blocks[0]));
  auto const entries =
      fromBlocksToUserActions(gsl::make_span(blocks).subspan(1));
  TC_RETURN((GetMeResult{trustchainCreation, entries}));
}

tc::cotask<std::vector<Trustchain::UserAction>> Requester::getUsers(
    gsl::span<Trustchain::UserId const> userIds)
{
  auto const response =
      TC_AWAIT(_client->emit("get users blocks", {{"user_ids", userIds}}));
  auto const ret =
      fromBlocksToUserActions(response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<std::vector<Trustchain::UserAction>> Requester::getUsers(
    gsl::span<Trustchain::DeviceId const> deviceIds)
{
  auto const response =
      TC_AWAIT(_client->emit("get users blocks", {{"device_ids", deviceIds}}));
  auto const ret =
      fromBlocksToUserActions(response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<std::vector<Trustchain::KeyPublishAction>>
Requester::getKeyPublishes(gsl::span<Trustchain::ResourceId const> resourceIds)
{
  auto const response = TC_AWAIT(
      _client->emit("get key publishes", {{"resource_ids", resourceIds}}));
  auto const ret =
      fromBlocksToKeyPublishActions(response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<void> Requester::authenticateSocketIO(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Crypto::SignatureKeyPair const& userSignatureKeyPair)
{
  FUNC_TIMER(Net);
  auto const challenge = TC_AWAIT(_client->emit("request auth challenge", {}))
                             .at("challenge")
                             .get<std::string>();
  // NOTE: It is MANDATORY to check this prefix is valid, or the server could
  // get us to sign anything!
  if (!boost::algorithm::starts_with(
          challenge, u8"\U0001F512 Auth Challenge. 1234567890."))
  {
    throw Errors::Exception(
        make_error_code(Errors::Errc::InternalError),
        "received auth challenge does not contain mandatory prefix, server "
        "may not be up to date, or we may be under attack.");
  }
  auto const signature =
      Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                   userSignatureKeyPair.privateKey);
  auto const request =
      nlohmann::json{{"signature", signature},
                     {"public_signature_key", userSignatureKeyPair.publicKey},
                     {"trustchain_id", trustchainId},
                     {"user_id", userId}};
  try
  {
    TC_AWAIT(_client->emit("authenticate device", request));
  }
  catch (Errors::Exception const& ex)
  {
    if (ex.errorCode().category() == Errors::ServerErrcCategory())
      throw Errors::formatEx(Errors::Errc::InternalError,
                             "device authentication failed {}",
                             ex.what());
  }
}

tc::cotask<void> Requester::authenticate(
    Trustchain::DeviceId const& deviceId,
    Crypto::SignatureKeyPair const& userSignatureKeyPair)
{
  FUNC_TIMER(Net);
  auto const baseTarget =
      fmt::format("devices/{deviceId:#S}", fmt::arg("deviceId", deviceId));
  auto const challenge =
      TC_AWAIT(_httpClient->asyncPost(fmt::format("{}/challenges", baseTarget)))
          .value()
          .at("challenge")
          .get<std::string>();
  // NOTE: It is MANDATORY to check this prefix is valid, or the server
  // could get us to sign anything!
  if (!boost::algorithm::starts_with(
          challenge, u8"\U0001F512 Auth Challenge. 1234567890."))
  {
    throw formatEx(
        Errors::Errc::InternalError,
        "received auth challenge does not contain mandatory prefix, server "
        "may not be up to date, or we may be under attack.");
  }
  auto const signature =
      Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                   userSignatureKeyPair.privateKey);
  auto accessToken =
      TC_AWAIT(_httpClient->asyncPost(
                   fmt::format("{}/sessions", baseTarget),
                   {{"signature", signature}, {"challenge", challenge}}))
          .value()
          .at("access_token")
          .get<std::string>();
  _httpClient->setAccessToken(std::move(accessToken));
}

tc::cotask<std::vector<
    std::tuple<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Requester::getPublicProvisionalIdentities(gsl::span<Email const> emails)
{
  std::vector<
      std::tuple<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  if (emails.empty())
    TC_RETURN(ret);

  nlohmann::json message;
  for (auto const& email : emails)
    message.push_back({{"type", "email"}, {"hashed_email", hashField(email)}});

  auto const result = TC_AWAIT(_client->emit(
      "get public provisional identities", nlohmann::json(message)));

  ret.reserve(result.size());
  for (auto const& elem : result)
    ret.emplace_back(
        elem.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
        elem.at("encryption_public_key").get<Crypto::PublicEncryptionKey>());
  TC_RETURN(ret);
}

}
