#pragma once

#include <Tanker/Test/Functional/Trustchain.hpp>

#include <Tanker/Admin.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Test
{
class TrustchainFactory
{
public:
  using Ptr = std::unique_ptr<TrustchainFactory>;

  static tc::cotask<Ptr> create();

  static TrustchainConfig loadTrustchainConfig(std::string const& path);
  static void saveTrustchainConfig(std::string const& path,
                                   TrustchainConfig const& config);

  tc::cotask<void> deleteTrustchain(Tanker::TrustchainId const& ic);
  tc::cotask<Trustchain::Ptr> createTrustchain(
      nonstd::optional<std::string> trustchainName = nonstd::nullopt,
      bool isTest = true);
  tc::cotask<Trustchain::Ptr> useTrustchain(std::string configPath);
  tc::cotask<VerificationCode> getVerificationCode(TrustchainId trustchainId,
                                                   Email const& email);

private:
  std::unique_ptr<Tanker::Admin> _admin;

  TrustchainFactory();
  TrustchainFactory(TrustchainFactory&&) = delete;
  TrustchainFactory& operator=(TrustchainFactory&&) = delete;
  TrustchainFactory(TrustchainFactory const&) = delete;
  TrustchainFactory& operator=(TrustchainFactory const&) = delete;
};
}
}
