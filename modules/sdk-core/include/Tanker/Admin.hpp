#pragma once

#include <Tanker/AConnection.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
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
#include <string>

namespace Tanker
{
class Admin
{
public:
  Admin(ConnectionPtr cx, std::string idToken);
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
  tc::cotask<void> deleteTrustchain(
      Trustchain::TrustchainId const& trustchainId);
  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block);
  tc::cotask<void> pushKeys(std::vector<std::vector<uint8_t>> const& block);
  tc::cotask<VerificationCode> getVerificationCode(
      Trustchain::TrustchainId const& tcId, Email const&);

  std::function<void()> connected;

private:
  ConnectionPtr _cx;
  std::string _idToken;

  tc::task_auto_canceler _taskCanceler;

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);
};
}
