#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Verification/IRequester.hpp>
#include <Tanker/Verification/Request.hpp>

#include <vector>

namespace Tanker
{
namespace Network
{
class HttpClient;
}

namespace Verification
{
class Requester : public IRequester
{
  Requester(Requester const&) = delete;
  Requester& operator=(Requester const&) = delete;
  Requester(Requester&&) = delete;
  Requester& operator=(Requester&&) = delete;

public:
  Requester(Network::HttpClient* httpClient);

  tc::cotask<std::optional<Crypto::PublicEncryptionKey>> userStatus(
      Trustchain::UserId const& userId) override;

  tc::cotask<void> setVerificationMethod(
      Trustchain::UserId const& userId,
      RequestWithVerif const& request) override;

  tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::UserId const& userId,
      RequestWithVerif const& verificationRequest) override;

  tc::cotask<std::vector<std::uint8_t>> fetchE2eVerificationKey(
      Trustchain::UserId const& userId,
      RequestWithVerif const& verificationRequest) override;

  tc::cotask<boost::variant2::variant<EncryptedVerificationKeyForUserKey,
                                      EncryptedVerificationKeyForUserSecret>>
  fetchEncryptedVerificationKey(Trustchain::UserId const& userId) override;

  tc::cotask<std::vector<boost::variant2::variant<VerificationMethod,
                                                  EncryptedVerificationMethod>>>
  fetchVerificationMethods(Trustchain::UserId const& userId) override;

  tc::cotask<Oidc::Challenge> getOidcChallenge(
      Trustchain::UserId const& userId, Oidc::Nonce const& nonce) override;

  tc::cotask<std::string> getSessionToken(
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> sessionCertificate,
      std::string nonce) override;

  tc::cotask<void> createUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      RequestWithVerif const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKeyForUserSecret) override;

  tc::cotask<void> createUserE2e(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      RequestWithVerif const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKeyForE2ePassphrase,
      gsl::span<uint8_t const> encryptedVerificationKeyForUserKey) override;

  tc::cotask<void> enrollUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<RequestWithVerif const> verificationRequests,
      gsl::span<uint8_t const> encryptedVerificationKey) override;

  tc::cotask<void> createDevice(
      gsl::span<uint8_t const> deviceCreation) override;

private:
  Network::HttpClient* _httpClient;
};
}
}
