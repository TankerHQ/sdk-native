#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/PhoneNumber.hpp>
#include <Tanker/Types/VerificationCode.hpp>

#include <fetchpp/client.hpp>
#include <fetchpp/http/url.hpp>

#include <tconcurrent/coroutine.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Tanker::Admin
{
struct App
{
  Trustchain::TrustchainId id;
  std::string authToken;
  std::optional<std::string> oidcProvider;
  std::optional<std::string> oidcClientId;
};

struct AppUpdateOptions
{
  std::optional<std::string> oidcProvider;
  std::optional<std::string> oidcClientId;
  std::optional<bool> sessionCertificates;
};

void from_json(nlohmann::json const& j, App& app);

class Client
{
public:
  Client(std::string_view url,
         std::string_view idToken,
         fetchpp::net::executor ex);
  void setIdToken(std::string_view idToken);

  tc::cotask<App> createTrustchain(std::string_view name,
                                   Crypto::SignatureKeyPair const& keypair,
                                   bool isTest);
  tc::cotask<App> createTrustchain(std::string_view name,
                                   Crypto::SignatureKeyPair const& keypair,
                                   std::string_view environmentId,
                                   bool isTest);
  tc::cotask<App> update(Trustchain::TrustchainId const& trustchainId,
                         AppUpdateOptions const& options);
  tc::cotask<void> deleteTrustchain(
      Trustchain::TrustchainId const& trustchainId);

private:
  fetchpp::http::url make_url(
      std::optional<Trustchain::TrustchainId> id = std::nullopt) const;
  fetchpp::http::url const _baseUrl;
  std::string _idToken;
  fetchpp::client _client;
};

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& authToken,
    Email const& email);

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& authToken,
    PhoneNumber const& phoneNumber);
}
