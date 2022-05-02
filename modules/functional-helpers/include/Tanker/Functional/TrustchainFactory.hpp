#pragma once

#include <Tanker/Functional/Trustchain.hpp>

#include <Tanker/Admin/Client.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Functional
{

enum class PSCProvider
{
  PSC_BAS,
  PSC_BAS_NO_EXPIRY,
};

std::string to_string(PSCProvider provider);

class TrustchainFactory
{
public:
  using Ptr = std::unique_ptr<TrustchainFactory>;

  static tc::cotask<Ptr> create();

  static TrustchainConfig loadTrustchainConfig(std::string const& path);
  static void saveTrustchainConfig(std::string const& path,
                                   TrustchainConfig const& config);

  tc::cotask<void> deleteTrustchain(Tanker::Trustchain::TrustchainId const& ic);
  tc::cotask<Trustchain::Ptr> createTrustchain(std::string const& name);
  tc::cotask<Trustchain::Ptr> useTrustchain(std::string configPath);
  tc::cotask<void> enableOidc(Tanker::Trustchain::TrustchainId const& id);
  tc::cotask<void> enablePSCOidc(Tanker::Trustchain::TrustchainId const& id,
                                 PSCProvider const& provider);
  tc::cotask<void> enablePreverifiedMethods(
      Tanker::Trustchain::TrustchainId const& id);
  tc::cotask<void> setUserEnrollmentEnabled(
      Tanker::Trustchain::TrustchainId const& id, bool state = true);

private:
  std::unique_ptr<Admin::Client> _admin;

  TrustchainFactory();
  TrustchainFactory(TrustchainFactory&&) = delete;
  TrustchainFactory& operator=(TrustchainFactory&&) = delete;
  TrustchainFactory(TrustchainFactory const&) = delete;
  TrustchainFactory& operator=(TrustchainFactory const&) = delete;
};
}
}
