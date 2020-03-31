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
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Client* client);

  tc::cotask<std::vector<Trustchain::ServerEntry>> getClaimBlocks() override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail) override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Unlock::Request const& request) override;

private:
  Client* _client;
};
}
