#pragma once

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Unlock
{
class IRequester
{
public:
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

  virtual ~IRequester() = default;
};

}
