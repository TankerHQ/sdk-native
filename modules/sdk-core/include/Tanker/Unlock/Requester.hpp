#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Unlock/IRequester.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <vector>

namespace Tanker
{
class HttpClient;

namespace Unlock
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(HttpClient* httpClient);

  tc::cotask<std::optional<Crypto::PublicEncryptionKey>> userStatus(
      Trustchain::UserId const& userId) override;

  tc::cotask<void> setVerificationMethod(
      Trustchain::UserId const& userId,
      Unlock::Request const& request) override;

  tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::UserId const& userId,
      Unlock::Request const& verificationRequest) override;

  tc::cotask<std::vector<Unlock::VerificationMethod>> fetchVerificationMethods(
      Trustchain::UserId const& userId) override;

  tc::cotask<void> createUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      Unlock::Request const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKey) override;

  tc::cotask<void> createDevice(
      gsl::span<uint8_t const> deviceCreation) override;

private:
  HttpClient* _httpClient;
};
}
}
