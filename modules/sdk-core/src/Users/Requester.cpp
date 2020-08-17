
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
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

template <typename T>
std::vector<std::string> base64KeyPublishActions(std::vector<T> const& actions)
{
  std::vector<std::string> ret;
  ret.reserve(actions.size());
  std::transform(std::begin(actions),
                 std::end(actions),
                 std::back_inserter(ret),
                 [](auto const& block) {
                   return mgs::base64::encode(Serialization::serialize(block));
                 });
  return ret;
}
}

Requester::Requester(HttpClient* httpClient) : _httpClient(httpClient)
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

tc::cotask<Requester::GetResult> Requester::getRevokedDeviceHistory(
    Trustchain::DeviceId const& deviceId)
{
  auto url = _httpClient->makeUrl(
      fmt::format("devices/{:#S}/revoked-device-history", deviceId));
  auto const response = TC_AWAIT(_httpClient->asyncGet(url.href())).value();
  auto rootBlock =
      Serialization::deserialize<Trustchain::Actions::TrustchainCreation>(
          mgs::base64::decode(response.at("root").get<std::string>()));
  TC_RETURN(
      (GetResult{std::move(rootBlock),
                 fromBlocksToUserActions(
                     response.at("history").get<std::vector<std::string>>())}));
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

tc::cotask<void> Requester::postResourceKeys(Share::ShareActions const& actions)
{
  auto const url = _httpClient->makeUrl("resource-keys");
  auto const response =
      TC_AWAIT(_httpClient->asyncPost(
                   url.href(),
                   {{"key_publishes_to_user",
                     base64KeyPublishActions(actions.keyPublishesToUsers)},
                    {"key_publishes_to_user_group",
                     base64KeyPublishActions(actions.keyPublishesToUserGroups)},
                    {"key_publishes_to_provisional_user",
                     base64KeyPublishActions(
                         actions.keyPublishesToProvisionalUsers)}}))
          .value();
}

tc::cotask<void> Requester::revokeDevice(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation)
{
  auto const url = _httpClient->makeUrl("device-revocations");
  TC_AWAIT(
      _httpClient->asyncPost(
          url.href(),
          {{"device_revocation",
            mgs::base64::encode(Serialization::serialize(deviceRevocation))}}))
      .value();
}

tc::cotask<IRequester::GetEncryptionKeyResult> Requester::getEncryptionKey(
    Trustchain::UserId const& userId,
    Crypto::PublicSignatureKey const& ghostDevicePublicSignatureKey)
{
  using namespace fmt::literals;

  auto query = nlohmann::json{
      {"ghost_device_public_signature_key",
       mgs::base64url_nopad::encode(ghostDevicePublicSignatureKey)}};
  auto url = _httpClient->makeUrl(
      fmt::format("users/{userId:#S}/encryption-key", "userId"_a = userId));
  url.set_search(fetchpp::http::encode_query(query));
  auto const res = TC_AWAIT(_httpClient->asyncGet(url.href())).value();
  TC_RETURN((GetEncryptionKeyResult{
      res.at("encrypted_user_private_encryption_key")
          .get<Crypto::SealedPrivateEncryptionKey>(),
      res.at("ghost_device_id").get<Trustchain::DeviceId>()}));
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
