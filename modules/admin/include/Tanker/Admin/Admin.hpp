#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/VerificationCode.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional.hpp>
#include <string>

namespace Tanker
{
namespace Admin
{
class Admin
{
public:
  Admin(Network::ConnectionPtr cx, std::string idToken);
  Admin(Admin const&) = delete;
  Admin& operator=(Admin const&) = delete;
  Admin(Admin&&) = delete;
  Admin& operator=(Admin&&) = delete;

  tc::cotask<void> start();

  tc::cotask<void> authenticateCustomer(std::string const& idToken);
  tc::cotask<Trustchain::TrustchainId> createTrustchain(
      std::string const& name,
      Crypto::SignatureKeyPair const& keyPair,
      bool isTest,
      bool storePrivateKey);
  tc::cotask<void> update(Trustchain::TrustchainId const& trustchainId,
                          nonstd::optional<std::string> oidcClientId,
                          nonstd::optional<std::string> oidcProvider);
  tc::cotask<void> deleteTrustchain(
      Trustchain::TrustchainId const& trustchainId);
  tc::cotask<VerificationCode> getVerificationCode(
      Trustchain::TrustchainId const& tcId, Email const&);

  std::function<void()> connected;

private:
  Network::ConnectionPtr _cx;
  std::string _idToken;

  tc::task_auto_canceler _taskCanceler;

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);
};
}
}