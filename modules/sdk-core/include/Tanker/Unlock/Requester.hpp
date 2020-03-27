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
public:
  Requester(Client* client);

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

private:
  Client* _client;
};
}
}
