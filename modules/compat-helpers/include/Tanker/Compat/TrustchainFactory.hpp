#pragma once

#include <Tanker/Compat/Trustchain.hpp>

#include <Tanker/Admin.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Compat
{
class TrustchainFactory
{
  std::unique_ptr<Tanker::Admin> _admin;

public:
  TrustchainFactory(TrustchainFactory&&) = default;
  TrustchainFactory& operator=(TrustchainFactory&&) = default;

  static tc::future<TrustchainFactory> create();

  static TrustchainConfig loadTrustchainConfig(std::string const& path);
  static void saveTrustchainConfig(std::string const& path,
                                   TrustchainConfig const& config);

  tc::future<void> deleteTrustchain(Tanker::TrustchainId const& ic);
  tc::future<Trustchain::Ptr> createTrustchain(
      nonstd::optional<std::string> trustchainName = nonstd::nullopt,
      bool isTest = true);
  tc::future<Trustchain::Ptr> useTrustchain(std::string configPath);

private:
  void deleteTrustchain(Trustchain::Ptr);
  TrustchainFactory();
  TrustchainFactory(TrustchainFactory const&) = delete;
  TrustchainFactory& operator=(TrustchainFactory const&) = delete;
};
}
}
