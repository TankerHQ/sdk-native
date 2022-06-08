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
  Crypto::PrivateSignatureKey secret;
  std::optional<std::string> oidcProvider;
  std::optional<std::string> oidcClientId;
};

struct AppUpdateOptions
{
  std::optional<std::string> oidcProvider;
  std::optional<std::string> oidcClientId;
  std::optional<bool> preverifiedVerification;
  std::optional<bool> userEnrollment;
};

void from_json(nlohmann::json const& j, App& app);

class Client
{
public:
  Client(std::string_view appManagementUrl,
         std::string_view appManagementToken,
         std::string_view environmentName,
         fetchpp::net::any_io_executor ex);

  tc::cotask<App> createTrustchain(std::string_view name);
  tc::cotask<App> update(Trustchain::TrustchainId const& trustchainId,
                         AppUpdateOptions const& options);
  tc::cotask<void> deleteTrustchain(
      Trustchain::TrustchainId const& trustchainId);

private:
  fetchpp::http::url make_url(
      std::optional<Trustchain::TrustchainId> id = std::nullopt) const;
  fetchpp::http::url const _baseUrl;
  std::string _appManagementToken;
  std::string _environmentName;
  fetchpp::client _client;
};

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& verificationApiToken,
    Email const& email);

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& verificationApiToken,
    PhoneNumber const& phoneNumber);
}
