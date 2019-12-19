#pragma once

#include <Tanker/Users/IRequester.hpp>

#include <Tanker/Client.hpp>

namespace Tanker
{

namespace Users
{
void from_json(nlohmann::json const& j, UserStatusResult& result);

class Requester : public IRequester
{
public:
  Requester(Client* client);

  tc::cotask<std::vector<Trustchain::ServerEntry>> getMe() override;
  tc::cotask<void> authenticate(Trustchain::TrustchainId const& trustchainId,
                                LocalUser const& localUser) override;
  tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey) override;

private:
  Client* _client;
};
}
}
