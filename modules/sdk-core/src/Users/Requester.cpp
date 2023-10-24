
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Utils.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <fmt/format.h>
#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>
#include <range/v3/functional/compose.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

namespace Tanker::Users
{
namespace
{
std::vector<Trustchain::UserAction> fromBlocksToUserActions(
    gsl::span<std::string const> blocks)
{
  return blocks |
         ranges::views::transform(ranges::compose(
             &Trustchain::deserializeUserAction, mgs::base64::lazy_decode())) |
         ranges::to<std::vector>;
}

std::vector<Trustchain::KeyPublishAction> fromBlocksToKeyPublishActions(
    gsl::span<std::string const> blocks)
{
  return blocks |
         ranges::views::transform(
             ranges::compose(&Trustchain::deserializeKeyPublishAction,
                             mgs::base64::lazy_decode())) |
         ranges::to<std::vector>;
}

template <typename T>
std::vector<std::string> base64KeyPublishActions(std::vector<T> const& actions)
{
  return actions | ranges::views::transform([](auto const& action) {
           return mgs::base64::encode(Serialization::serialize(action));
         }) |
         ranges::to<std::vector>;
}
}

Requester::Requester(Network::HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<Requester::GetResult> Requester::getUsersImpl(
    nlohmann::json const& query)
{
  auto url = _httpClient->makeUrl("user-histories", query);
  auto const response = TC_AWAIT(_httpClient->asyncGet(url)).value();
  auto rootBlock =
      Serialization::deserialize<Trustchain::Actions::TrustchainCreation>(
          mgs::base64::decode(response.at("root").get<std::string>()));
  TC_RETURN((GetResult{
      std::move(rootBlock),
      fromBlocksToUserActions(
          response.at("histories").get<std::vector<std::string>>())}));
}

tc::cotask<Requester::GetResult> Requester::getUsers(
    gsl::span<Trustchain::UserId const> userIds, IsLight isLight)
{
  auto const query = nlohmann::json{
      {"user_ids[]",
       userIds | ranges::views::transform(mgs::base64url_nopad::lazy_encode())},
      {"is_light", isLight == IsLight::Yes ? "true" : "false"}};
  TC_RETURN(TC_AWAIT(getUsersImpl(query)));
}

tc::cotask<Requester::GetResult> Requester::getUsers(
    gsl::span<Trustchain::DeviceId const> deviceIds, IsLight isLight)
{
  auto const query = nlohmann::json{
      {"device_ids[]",
       deviceIds |
           ranges::views::transform(mgs::base64url_nopad::lazy_encode())},
      {"is_light", isLight == IsLight::Yes ? "true" : "false"}};
  TC_RETURN(TC_AWAIT(getUsersImpl(query)));
}

tc::cotask<std::vector<Trustchain::KeyPublishAction>>
Requester::getKeyPublishes(
    gsl::span<Crypto::SimpleResourceId const> resourceIds)
{
  auto const query =
      nlohmann::json{{"resource_ids[]",
                      resourceIds | ranges::views::transform(
                                        mgs::base64url_nopad::lazy_encode())}};
  auto url = _httpClient->makeUrl("resource-keys", query);
  auto const response = TC_AWAIT(_httpClient->asyncGet(url)).value();
  TC_RETURN(fromBlocksToKeyPublishActions(
      response.at("resource_keys").get<std::vector<std::string>>()));
}

tc::cotask<void> Requester::postResourceKeys(Share::ShareActions const& actions)
{
  auto const response =
      TC_AWAIT(_httpClient->asyncPost(
                   _httpClient->makeUrl("resource-keys"),
                   {{"key_publishes_to_user",
                     base64KeyPublishActions(actions.keyPublishesToUsers)},
                    {"key_publishes_to_user_group",
                     base64KeyPublishActions(actions.keyPublishesToUserGroups)},
                    {"key_publishes_to_provisional_user",
                     base64KeyPublishActions(
                         actions.keyPublishesToProvisionalUsers)}}))
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
      fmt::format("users/{userId:#S}/encryption-key", "userId"_a = userId),
      query);
  auto const res = TC_AWAIT(_httpClient->asyncUnauthGet(url)).value();
  TC_RETURN((GetEncryptionKeyResult{
      res.at("encrypted_user_private_encryption_key")
          .get<Crypto::SealedPrivateEncryptionKey>(),
      res.at("ghost_device_id").get<Trustchain::DeviceId>()}));
}

tc::cotask<std::map<
    HashedEmail,
    std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Requester::getPublicProvisionalIdentities(
    gsl::span<HashedEmail const> hashedEmails)
{
  std::map<HashedEmail,
           std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  if (hashedEmails.empty())
    TC_RETURN(ret);

  auto query = nlohmann::json{
      {"hashed_emails",
       hashedEmails | ranges::views::transform(mgs::base64::lazy_encode())}};
  auto url = _httpClient->makeUrl("public-provisional-identities");
  auto const result = TC_AWAIT(_httpClient->asyncPost(url, query)).value();
  auto const publicIdentitites = result.at("public_provisional_identities");
  for (auto const& elem : publicIdentitites.at("hashed_emails"))
  {
    auto const hashedEmail = elem.at("value").get<HashedEmail>();
    auto const publicSignatureKey =
        elem.at("public_signature_key").get<Crypto::PublicSignatureKey>();
    auto const publicEncryptionKey =
        elem.at("public_encryption_key").get<Crypto::PublicEncryptionKey>();
    ret[hashedEmail] = {publicSignatureKey, publicEncryptionKey};
  }
  TC_RETURN(ret);
}

tc::cotask<std::map<
    HashedPhoneNumber,
    std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Requester::getPublicProvisionalIdentities(
    gsl::span<HashedPhoneNumber const> hashedPhoneNumbers)
{
  std::map<HashedPhoneNumber,
           std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  if (hashedPhoneNumbers.empty())
    TC_RETURN(ret);

  auto query =
      nlohmann::json{{"hashed_phone_numbers",
                      hashedPhoneNumbers | ranges::views::transform(
                                               mgs::base64::lazy_encode())}};
  auto url = _httpClient->makeUrl("public-provisional-identities");
  auto const result = TC_AWAIT(_httpClient->asyncPost(url, query)).value();
  auto const publicIdentitites = result.at("public_provisional_identities");
  for (auto const& elem : publicIdentitites.at("hashed_phone_numbers"))
  {
    auto const hashedPhoneNumber = elem.at("value").get<HashedPhoneNumber>();
    auto const publicSignatureKey =
        elem.at("public_signature_key").get<Crypto::PublicSignatureKey>();
    auto const publicEncryptionKey =
        elem.at("public_encryption_key").get<Crypto::PublicEncryptionKey>();
    ret[hashedPhoneNumber] = {publicSignatureKey, publicEncryptionKey};
  }
  TC_RETURN(ret);
}
}
