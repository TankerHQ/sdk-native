#pragma once

#include <Tanker/AConnection.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Types/VerificationCode.hpp>

#include <boost/signals2/signal.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace Tanker
{
class Admin
{
public:
  Admin(ConnectionPtr cx, std::string idToken);
  Admin(Admin&&) = default;
  Admin& operator=(Admin&&) = default;

  tc::cotask<void> start();

  tc::cotask<void> authenticateCustomer(std::string const& idToken);
  tc::cotask<TrustchainId> createTrustchain(
      std::string const& name,
      Crypto::SignatureKeyPair const& keyPair,
      bool isTest = true);
  tc::cotask<void> deleteTrustchain(TrustchainId const& trustchainId);
  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block);
  tc::cotask<void> pushKeys(std::vector<std::vector<uint8_t>> const& block);
  tc::cotask<VerificationCode> getVerificationCode(TrustchainId const& tcId,
                                                   Email const&);

  boost::signals2::signal<void()> connected;

private:
  ConnectionPtr _cx;
  std::string _idToken;

  tc::task_auto_canceler _taskCanceler;

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);
};
}
