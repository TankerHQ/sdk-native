#include <Tanker/ProvisionalUsers/Requester.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <mgs/base64.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::ProvisionalUsers
{
Requester::Requester(Network::HttpClient* httpClient) : _httpClient(httpClient)
{
}

tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>> Requester::getClaimBlocks(
    Trustchain::UserId const& userId)
{
  auto const target =
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/provisional-identity-claims", fmt::arg("userId", userId)));
  auto const res = TC_AWAIT(_httpClient->asyncGet(target));
  auto decodedClaims = res.value().at("provisional_identity_claims") | ranges::views::transform([](auto const& block) {
                         return Serialization::deserialize<Trustchain::Actions::ProvisionalIdentityClaim>(
                             mgs::base64::decode(block.template get<std::string>()));
                       });
  TC_RETURN(decodedClaims | ranges::to<std::vector>);
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>> Requester::getVerifiedProvisionalIdentityKeys(
    Trustchain::UserId const& userId, Verification::RequestWithSession const& request)
{
  auto const res = TC_AWAIT(_httpClient->asyncPost(
      _httpClient->makeUrl(fmt::format("users/{userId:#S}/tanker-provisional-keys", fmt::arg("userId", userId))),
      request));

  auto const& j = res.value();
  if (j.empty())
    TC_RETURN(std::nullopt);

  auto& jProvisional = j.at("tanker_provisional_keys");
  TC_RETURN(std::make_optional(
      TankerSecretProvisionalIdentity{{jProvisional.at("public_encryption_key").get<Crypto::PublicEncryptionKey>(),
                                       jProvisional.at("private_encryption_key").get<Crypto::PrivateEncryptionKey>()},
                                      {jProvisional.at("public_signature_key").get<Crypto::PublicSignatureKey>(),
                                       jProvisional.at("private_signature_key").get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<TankerSecretProvisionalIdentity> Requester::getProvisionalIdentityKeys(
    Verification::RequestWithVerif const& request)
{
  auto const res =
      TC_AWAIT(_httpClient->asyncPost(_httpClient->makeUrl("tanker-provisional-keys"), {{"verification", request}}));

  auto const& json = res.value();

  auto& jProvisional = json.at("tanker_provisional_keys");
  TC_RETURN(
      (TankerSecretProvisionalIdentity{{jProvisional.at("public_encryption_key").get<Crypto::PublicEncryptionKey>(),
                                        jProvisional.at("private_encryption_key").get<Crypto::PrivateEncryptionKey>()},
                                       {jProvisional.at("public_signature_key").get<Crypto::PublicSignatureKey>(),
                                        jProvisional.at("private_signature_key").get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<void> Requester::claimProvisionalIdentity(Trustchain::Actions::ProvisionalIdentityClaim const& claimAction)
{
  auto const serialized = Serialization::serialize(claimAction);
  nlohmann::json body{{"provisional_identity_claim", mgs::base64::encode(serialized)}};

  TC_AWAIT(_httpClient->asyncPost(_httpClient->makeUrl("provisional-identity-claims"), std::move(body))).value();
  TC_RETURN();
}
}
