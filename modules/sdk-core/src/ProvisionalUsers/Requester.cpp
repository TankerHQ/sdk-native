#include <Tanker/ProvisionalUsers/Requester.hpp>

#include <Tanker/Client.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::ProvisionalUsers
{
Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<std::vector<Trustchain::ServerEntry>> Requester::getClaimBlocks()
{
  auto const response = TC_AWAIT(_client->emit("get my claim blocks", {}));
  auto const ret = Trustchain::fromBlocksToServerEntries(
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

tc::cotask<void> Requester::pushBlock(gsl::span<uint8_t const> block)
{
  TC_AWAIT(
      _client->emit("push block", cppcodec::base64_rfc4648::encode(block)));
}
}
