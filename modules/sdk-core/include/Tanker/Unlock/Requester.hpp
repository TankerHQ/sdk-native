#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Unlock/IRequester.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <vector>

namespace Tanker
{
class Client;

namespace Unlock
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Client* client);

  tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey) override;

  tc::cotask<void> setVerificationMethod(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& request) override;

  tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& verificationRequest) override;

  tc::cotask<std::vector<Unlock::VerificationMethod>> fetchVerificationMethods(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId) override;

  tc::cotask<void> createUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      Unlock::Request const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKey) override;

private:
  Client* _client;
};
}
}
