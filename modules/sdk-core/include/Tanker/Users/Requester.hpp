#pragma once

#include <Tanker/Users/IRequester.hpp>

namespace Tanker
{
struct DeviceKeys;
class Client;
class HttpClient;

namespace Users
{

class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Client* client, HttpClient* httpClient);

  tc::cotask<GetMeResult> getMe() override;
  tc::cotask<std::vector<Trustchain::UserAction>> getUsers(
      gsl::span<Trustchain::UserId const> userIds) override;
  tc::cotask<std::vector<Trustchain::UserAction>> getUsers(
      gsl::span<Trustchain::DeviceId const> deviceIds) override;
  tc::cotask<std::vector<Trustchain::KeyPublishAction>> getKeyPublishes(
      gsl::span<Trustchain::ResourceId const> resourceIds) override;
  tc::cotask<void> authenticateSocketIO(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::SignatureKeyPair const& userSignatureKeyPair) override;
  tc::cotask<void> authenticate(
      Trustchain::DeviceId const& deviceId,
      Crypto::SignatureKeyPair const& userSignatureKeyPair) override;

  tc::cotask<std::vector<
      std::tuple<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<Email const> emails) override;

private:
  Client* _client;
  HttpClient* _httpClient;
};
}
}
