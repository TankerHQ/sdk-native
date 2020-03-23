#pragma once

#include <Tanker/ProvisionalUsers/IRequester.hpp>

namespace Tanker
{
class Client;
}

namespace Tanker::ProvisionalUsers
{
class Requester : public IRequester
{
public:
  Requester(Client* client);

  tc::cotask<std::vector<Trustchain::ServerEntry>> getClaimBlocks() override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail) override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Unlock::Request const& request) override;
  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block) override;

private:
  Client* _client;
};
}
