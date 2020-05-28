#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>

namespace Tanker
{
struct DeviceKeys;
class Client;

namespace Users
{

class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Client* client);

  tc::cotask<GetMeResult> getMe() override;
  tc::cotask<std::vector<Trustchain::ServerEntry>> getUsers(
      gsl::span<Trustchain::UserId const> userIds) override;
  tc::cotask<std::vector<Trustchain::ServerEntry>> getUsers(
      gsl::span<Trustchain::DeviceId const> deviceIds) override;
  tc::cotask<std::vector<std::string>> getKeyPublishes(
      gsl::span<Trustchain::ResourceId const> resourceIds) override;
  tc::cotask<void> authenticate(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::SignatureKeyPair const& userSignatureKeyPair) override;

  tc::cotask<std::vector<
      std::tuple<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<Email const> emails) override;

private:
  Client* _client;
};
}
}
