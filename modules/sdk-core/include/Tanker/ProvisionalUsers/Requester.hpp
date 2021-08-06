#pragma once

#include <Tanker/ProvisionalUsers/IRequester.hpp>

namespace Tanker
{
namespace Network
{
class HttpClient;
}

namespace ProvisionalUsers
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Network::HttpClient* httpClient);

  tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
  getClaimBlocks(Trustchain::UserId const& userId) override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys() override;
  tc::cotask<TankerSecretProvisionalIdentity> getProvisionalIdentityKeys(
      Unlock::RequestWithVerif const& request) override;
  tc::cotask<void> claimProvisionalIdentity(
      Trustchain::Actions::ProvisionalIdentityClaim const& claimAction)
      override;

private:
  Network::HttpClient* _httpClient;
};
}
}
