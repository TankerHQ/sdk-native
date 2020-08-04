#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Unlock
{
struct UserStatusResult
{
  bool deviceExists;
  bool userExists;
  Crypto::Hash lastReset;
};

class IRequester
{
public:
  virtual tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey) = 0;

  virtual tc::cotask<void> setVerificationMethod(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& request) = 0;

  virtual tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& verificationRequest) = 0;

  virtual tc::cotask<std::vector<Unlock::VerificationMethod>>
  fetchVerificationMethods(Trustchain::TrustchainId const& trustchainId,
                           Trustchain::UserId const& userId) = 0;

  virtual tc::cotask<void> createUser(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      Unlock::Request const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKey) = 0;

  virtual tc::cotask<void> createDevice(
      Trustchain::TrustchainId const& trustchainId,
      gsl::span<uint8_t const> deviceCreation) = 0;

  virtual ~IRequester() = default;
};

}
