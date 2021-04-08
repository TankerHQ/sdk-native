#include <Tanker/ProvisionalUsers/Requester.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <mgs/base64.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::ProvisionalUsers
{
namespace
{
std::vector<Trustchain::Actions::ProvisionalIdentityClaim>
fromBlocksToProvisionalIdentityClaims(std::vector<std::string> const& blocks)
{
  std::vector<Trustchain::Actions::ProvisionalIdentityClaim> entries;
  entries.reserve(blocks.size());
  std::transform(std::begin(blocks),
                 std::end(blocks),
                 std::back_inserter(entries),
                 [](auto const& block) {
                   return Serialization::deserialize<
                       Trustchain::Actions::ProvisionalIdentityClaim>(
                       mgs::base64::decode(block));
                 });

  return entries;
}
}

Requester::Requester(HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
Requester::getClaimBlocks(Trustchain::UserId const& userId)
{
  auto const target =
      fmt::format("users/{userId:#S}/provisional-identity-claims",
                  fmt::arg("userId", userId));
  auto const res = TC_AWAIT(_httpClient->asyncGet(target));
  auto ret = fromBlocksToProvisionalIdentityClaims(
      res.value()
          .at("provisional_identity_claims")
          .get<std::vector<std::string>>());
  TC_RETURN(std::move(ret));
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Requester::getVerifiedProvisionalIdentityKeys()
{
  auto const res = TC_AWAIT(_httpClient->asyncPost("provisional-identities"));

  auto const j = res.value();
  if (j.empty())
    TC_RETURN(std::nullopt);

  auto& jProvisional = j.at("provisional_identity");
  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {jProvisional.at("public_encryption_key")
           .get<Crypto::PublicEncryptionKey>(),
       jProvisional.at("private_encryption_key")
           .get<Crypto::PrivateEncryptionKey>()},
      {jProvisional.at("public_signature_key")
           .get<Crypto::PublicSignatureKey>(),
       jProvisional.at("private_signature_key")
           .get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Requester::getProvisionalIdentityKeys(Unlock::Request const& request)
{
  auto const res = TC_AWAIT(_httpClient->asyncPost(
      "provisional-identities", {{"verification", request}}));

  if (res.has_error() &&
      res.error().ec == Errors::AppdErrc::ProvisionalIdentityNotFound)
    TC_RETURN(std::nullopt);
  auto const json = res.value();

  auto& jProvisional = json.at("provisional_identity");
  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {jProvisional.at("public_encryption_key")
           .get<Crypto::PublicEncryptionKey>(),
       jProvisional.at("private_encryption_key")
           .get<Crypto::PrivateEncryptionKey>()},
      {jProvisional.at("public_signature_key")
           .get<Crypto::PublicSignatureKey>(),
       jProvisional.at("private_signature_key")
           .get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<void> Requester::claimProvisionalIdentity(
    Trustchain::Actions::ProvisionalIdentityClaim const& claimAction)
{
  auto const serialized = Serialization::serialize(claimAction);
  nlohmann::json body{
      {"provisional_identity_claim", mgs::base64::encode(serialized)}};

  TC_AWAIT(
      _httpClient->asyncPost("provisional-identity-claims", std::move(body)))
      .value();
  TC_RETURN();
}
}
