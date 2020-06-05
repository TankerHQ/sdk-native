#include <Tanker/ProvisionalUsers/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>

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
                       cppcodec::base64_rfc4648::decode(block));
                 });

  return entries;
}
}

Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
Requester::getClaimBlocks()
{
  auto const response = TC_AWAIT(_client->emit("get my claim blocks", {}));
  auto const ret = fromBlocksToProvisionalIdentityClaims(
      response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Requester::getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail)
{
  nlohmann::json body = {{"verification_method",
                          {{"type", "email"}, {"hashed_email", hashedEmail}}}};
  auto const json =
      TC_AWAIT(_client->emit("get verified provisional identity", body));

  if (json.empty())
    TC_RETURN(std::nullopt);

  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {json.at("encryption_public_key").get<Crypto::PublicEncryptionKey>(),
       json.at("encryption_private_key").get<Crypto::PrivateEncryptionKey>()},
      {json.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
       json.at("signature_private_key").get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Requester::getProvisionalIdentityKeys(Unlock::Request const& request)
{
  auto const json = TC_AWAIT(
      _client->emit("get provisional identity", {{"verification", request}}));

  if (json.empty())
    TC_RETURN(std::nullopt);

  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {json.at("encryption_public_key").get<Crypto::PublicEncryptionKey>(),
       json.at("encryption_private_key").get<Crypto::PrivateEncryptionKey>()},
      {json.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
       json.at("signature_private_key").get<Crypto::PrivateSignatureKey>()}}));
}
}
