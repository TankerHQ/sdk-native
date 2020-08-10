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

  tc::cotask<GetResult> getUsers(
      gsl::span<Trustchain::UserId const> userIds) override;
  tc::cotask<GetResult> getUsers(
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
  tc::cotask<void> revokeDevice(
      Trustchain::Actions::DeviceRevocation const& deviceRevocation) override;

  tc::cotask<std::map<
      Crypto::Hash,
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(
      gsl::span<Crypto::Hash const> hashedEmails) override;

private:
  tc::cotask<GetResult> getUsersImpl(nlohmann::json const& query);

  Client* _client;
  HttpClient* _httpClient;
};
}
}
