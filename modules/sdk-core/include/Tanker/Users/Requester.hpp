#pragma once

#include <Tanker/Users/IRequester.hpp>

namespace Tanker
{
struct DeviceKeys;

namespace Network
{
class HttpClient;
}

namespace Users
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Network::HttpClient* httpClient);

  tc::cotask<GetResult> getUsers(gsl::span<Trustchain::UserId const> userIds) override;
  tc::cotask<GetResult> getUsers(gsl::span<Trustchain::DeviceId const> deviceIds) override;
  tc::cotask<std::vector<Trustchain::KeyPublishAction>> getKeyPublishes(
      gsl::span<Crypto::SimpleResourceId const> resourceIds) override;
  tc::cotask<void> postResourceKeys(Share::ShareActions const& resourceKeys) override;
  tc::cotask<GetEncryptionKeyResult> getEncryptionKey(
      Trustchain::UserId const& userId, Crypto::PublicSignatureKey const& ghostDevicePublicSignatureKey) override;

  tc::cotask<std::map<HashedEmail, std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<HashedEmail const> hashedEmails) override;

  tc::cotask<std::map<HashedPhoneNumber, std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<HashedPhoneNumber const> hashedPhoneNumbers) override;

private:
  tc::cotask<GetResult> getUsersImpl(nlohmann::json const& query);

  Network::HttpClient* _httpClient;
};
}
}
