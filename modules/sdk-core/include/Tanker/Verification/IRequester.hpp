#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Verification/Request.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker::Verification
{
class IRequester
{
public:
  virtual tc::cotask<std::optional<Crypto::PublicEncryptionKey>> userStatus(
      Trustchain::UserId const& userId) = 0;

  virtual tc::cotask<void> setVerificationMethod(
      Trustchain::UserId const& userId, RequestWithVerif const& request) = 0;

  virtual tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::UserId const& userId,
      RequestWithVerif const& verificationRequest) = 0;

  virtual tc::cotask<std::vector<VerificationMethod>> fetchVerificationMethods(
      Trustchain::UserId const& userId) = 0;

  virtual tc::cotask<std::string> getSessionToken(
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> sessionCertificate,
      std::string nonce) = 0;

  virtual tc::cotask<void> createUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      RequestWithVerif const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKey) = 0;

  virtual tc::cotask<void> createDevice(
      gsl::span<uint8_t const> deviceCreation) = 0;

  virtual ~IRequester() = default;
};

}