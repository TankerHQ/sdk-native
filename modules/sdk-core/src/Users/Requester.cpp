
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrcCategory.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Utils.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <fmt/format.h>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Users
{
namespace
{
std::vector<Trustchain::UserAction> fromBlocksToUserActions(
    gsl::span<std::string const> blocks)
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
    gsl::span<std::string const> blocks)
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

tc::cotask<Requester::GetResult> Requester::getUsersImpl(
    nlohmann::json const& query)
{
  auto url = _httpClient->makeUrl("user-histories");
  url.set_search(fetchpp::http::encode_query(query));
  auto const response = TC_AWAIT(_httpClient->asyncGet(url.href())).value();
  auto rootBlock =
      Serialization::deserialize<Trustchain::Actions::TrustchainCreation>(
          mgs::base64::decode(response.at("root").get<std::string>()));
  TC_RETURN((GetResult{
      std::move(rootBlock),
      fromBlocksToUserActions(
          response.at("histories").get<std::vector<std::string>>())}));
}

tc::cotask<Requester::GetResult> Requester::getUsers(
    gsl::span<Trustchain::UserId const> userIds)
{
  auto const query = nlohmann::json{
      {"user_ids[]", encodeCryptoTypes<mgs::base64url_nopad>(userIds)}};
  TC_RETURN(TC_AWAIT(getUsersImpl(query)));
}

tc::cotask<Requester::GetResult> Requester::getUsers(
    gsl::span<Trustchain::DeviceId const> deviceIds)
{
  auto const query = nlohmann::json{
      {"device_ids[]", encodeCryptoTypes<mgs::base64url_nopad>(deviceIds)}};
  TC_RETURN(TC_AWAIT(getUsersImpl(query)));
}

tc::cotask<std::vector<Trustchain::KeyPublishAction>>
Requester::getKeyPublishes(gsl::span<Trustchain::ResourceId const> resourceIds)
{
  auto const query = nlohmann::json{
      {"resource_ids[]", encodeCryptoTypes<mgs::base64url_nopad>(resourceIds)}};
  auto url = _httpClient->makeUrl("resource-keys");
  url.set_search(fetchpp::http::encode_query(query));
  auto const response = TC_AWAIT(_httpClient->asyncGet(url.href())).value();
  TC_RETURN(fromBlocksToKeyPublishActions(
      response.at("resource_keys").get<std::vector<std::string>>()));
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

tc::cotask<std::map<
    Crypto::Hash,
    std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Requester::getPublicProvisionalIdentities(
    gsl::span<Crypto::Hash const> hashedEmails)
{
  std::map<Crypto::Hash,
           std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  if (hashedEmails.empty())
    TC_RETURN(ret);

  auto query =
      nlohmann::json{{"hashed_emails[]",
                      encodeCryptoTypes<mgs::base64url_nopad>(hashedEmails)}};
  auto url = _httpClient->makeUrl("public-provisional-identities");
  url.set_search(fetchpp::http::encode_query(query));
  auto const result = TC_AWAIT(_httpClient->asyncGet(url.href())).value();

  for (auto const& elem : result.at("public_provisional_identities"))
  {
    auto const hashedEmail = elem.at("hashed_email").get<Crypto::Hash>();
    auto const publicSignatureKey =
        elem.at("public_signature_key").get<Crypto::PublicSignatureKey>();
    auto const publicEncryptionKey =
        elem.at("public_encryption_key").get<Crypto::PublicEncryptionKey>();
    ret[hashedEmail] = {publicSignatureKey, publicEncryptionKey};
  }
  TC_RETURN(ret);
}
}
