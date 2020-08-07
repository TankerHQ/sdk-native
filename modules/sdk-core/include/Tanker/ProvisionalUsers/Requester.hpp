#pragma once

#include <Tanker/ProvisionalUsers/IRequester.hpp>

namespace Tanker
{
class HttpClient;
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
  Requester(HttpClient* httpClient);

  tc::cotask<std::vector<Trustchain::Actions::ProvisionalIdentityClaim>>
  getClaimBlocks(Trustchain::UserId const& userId) override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys() override;
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Unlock::Request const& request) override;
  tc::cotask<void> claimProvisionalIdentity(
      Trustchain::Actions::ProvisionalIdentityClaim const& claimAction)
      override;

private:
  HttpClient* _httpClient;
};
}
