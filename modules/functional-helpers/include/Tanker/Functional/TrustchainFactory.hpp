#pragma once

#include <Tanker/Functional/Trustchain.hpp>

#include <Tanker/Admin/Admin.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Functional
{
class TrustchainFactory
{
public:
  using Ptr = std::unique_ptr<TrustchainFactory>;

  static tc::cotask<Ptr> create();

  static TrustchainConfig loadTrustchainConfig(std::string const& path);
  static void saveTrustchainConfig(std::string const& path,
                                   TrustchainConfig const& config);

  tc::cotask<void> deleteTrustchain(Tanker::Trustchain::TrustchainId const& ic);
  tc::cotask<Trustchain::Ptr> createTrustchain(
      std::optional<std::string> trustchainName = std::nullopt,
      bool isTest = true,
      bool storePrivateKey = true);
  tc::cotask<Trustchain::Ptr> useTrustchain(std::string configPath);
  tc::cotask<VerificationCode> getVerificationCode(
      Tanker::Trustchain::TrustchainId const& trustchainId, Email const& email);
  tc::cotask<void> enableOidc(Tanker::Trustchain::TrustchainId const& id);

private:
  std::unique_ptr<Admin::Admin> _admin;

  TrustchainFactory();
  TrustchainFactory(TrustchainFactory&&) = delete;
  TrustchainFactory& operator=(TrustchainFactory&&) = delete;
  TrustchainFactory(TrustchainFactory const&) = delete;
  TrustchainFactory& operator=(TrustchainFactory const&) = delete;
};
}
}
