#include <Tanker/Admin/Client.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Tanker/Log/Log.hpp>

#include <nlohmann/json.hpp>

#include <chrono>

TLOG_CATEGORY(Admin);

namespace Tanker::Admin
{
using namespace Tanker::Errors;

namespace
{
struct ServerErrorMessage
{
  std::string code;
  int status;
  std::string message;
  std::string requestId;
};

void from_json(nlohmann::json const& j, ServerErrorMessage& msg)
{
  j.at("code").get_to(msg.code);
  msg.status = j.at("status").get<int>();
  j.at("message").get_to(msg.message);
  j.at("trace_id").get_to(msg.requestId);
}

auto errorReport(Errors::AppdErrc err_code,
                 std::string_view customMessage,
                 tcurl::read_all_result const& response)
{
  try
  {
    auto const json =
        nlohmann::json::parse(response.data.begin(), response.data.end());
    auto const serverMsg = json.at("error").get<ServerErrorMessage>();
    return Errors::formatEx(err_code,
                            "{}: {} {}",
                            customMessage,
                            serverMsg.code,
                            serverMsg.message);
  }
  catch (...)
  {
    return Errors::formatEx(
        err_code,
        "{}: invalid error: {}",
        customMessage,
        std::string(response.data.begin(), response.data.end()));
  }
}
}
void from_json(nlohmann::json const& j, OidcConfiguration& config)
{
  if (auto value = j.at("display_name").get<std::string>(); !value.empty())
    config.displayName = value;
  if (auto value = j.at("client_id").get<std::string>(); !value.empty())
    config.clientId = value;
  if (auto value = j.at("issuer").get<std::string>(); !value.empty())
    config.issuer = value;
}
void from_json(nlohmann::json const& j, App& app)
{
  j.at("id").get_to(app.id);
  j.at("secret").get_to(app.secret);
  j.at("oidc_providers").get_to(app.oidcProviders);
}

Client::Client(std::string_view appManagementUrl,
               std::string_view appManagementToken,
               std::string_view environmentName)
  : _baseUrl(fmt::format("{}/v2/apps", appManagementUrl)),
    _appManagementToken(appManagementToken),
    _environmentName(environmentName)
{
}

std::string Client::make_url(std::optional<Trustchain::TrustchainId> id) const
{
  if (id)
    return fmt::format("{}/{:#S}", _baseUrl, id.value());
  return _baseUrl;
}

tc::cotask<App> Client::createTrustchain(std::string_view name)
{
  auto message =
      nlohmann::json{
          {"name", name},
          {"environment_name", _environmentName},
      }
          .dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url(make_url());
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());
  request->add_header(
      fmt::format("Authorization: Bearer {}", _appManagementToken));
  request->add_header("Content-type: application/json");

  auto const response = TC_AWAIT(tcurl::read_all(_client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode == 201)
  {
    auto const jresponse =
        nlohmann::json::parse(response.data.begin(), response.data.end());
    auto app = jresponse.at("app").get<App>();
    TINFO("created trustchain {} {:#S} on environment {}",
          name,
          app.id,
          _environmentName);
    TC_RETURN(app);
  }

  throw errorReport(
      Errors::AppdErrc::InternalError, "could not create trustchain", response);
}

tc::cotask<void> Client::deleteTrustchain(
    Trustchain::TrustchainId const& trustchainId)
{
  auto request = std::make_shared<tcurl::request>();
  request->set_url(make_url(trustchainId));
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "DELETE");
  request->add_header(
      fmt::format("Authorization: Bearer {}", _appManagementToken));

  TINFO("deleting trustchain {:#S}", trustchainId);
  auto response = TC_AWAIT(tcurl::read_all(_client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode == 200)
    TC_RETURN();
  throw errorReport(
      Errors::AppdErrc::InternalError, "could not delete trustchain", response);
}

tc::cotask<App> Client::update(Trustchain::TrustchainId const& trustchainId,
                               AppUpdateOptions const& options)
{
  TINFO("updating trustchain {:#S}", trustchainId);
  auto body = nlohmann::json{};
  if (options.oidcProvider) {
    auto const& provider = options.oidcProvider.value();
    bool ignoreTokenExpiration = provider.displayName == "pro-sante-bas-no-expiry";
    auto providerJson = nlohmann::json{
        {"client_id", provider.clientId},
        {"issuer", provider.issuer},
        {"display_name", provider.displayName},
        {"ignore_token_expiration", ignoreTokenExpiration}
    };
    body["oidc_providers"] = nlohmann::json::array({providerJson});
  }

  if (options.preverifiedVerification)
    body["preverified_verification_enabled"] = *options.preverifiedVerification;
  if (options.userEnrollment)
    body["enroll_users_enabled"] = *options.userEnrollment;

  auto const message = body.dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url(make_url(trustchainId));
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "PATCH");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());
  request->add_header(
      fmt::format("Authorization: Bearer {}", _appManagementToken));
  request->add_header("Content-type: application/json");

  auto const response = TC_AWAIT(tcurl::read_all(_client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode == 200)
  {
    auto const jresponse =
        nlohmann::json::parse(response.data.begin(), response.data.end());
    TC_RETURN(jresponse.at("app"));
  }

  throw errorReport(
      Errors::AppdErrc::InternalError, "could not update trustchain", response);
}

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view host_url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& verificationApiToken,
    Email const& email)
{
  auto const body = nlohmann::json({{"email", email},
                                    {"app_id", appId},
                                    {"auth_token", verificationApiToken}});
  auto const message = body.dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url(fmt::format("{}/verification/email/code", host_url));
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());
  request->add_header("Content-type: application/json");

  tcurl::multi client;
  auto const response = TC_AWAIT(tcurl::read_all(client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode != 200)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "could not retrieve verification code for {}",
                           email);
  auto const jresponse =
      nlohmann::json::parse(response.data.begin(), response.data.end());
  TC_RETURN(jresponse.at("verification_code").get<std::string>());
}

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view host_url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& verificationApiToken,
    PhoneNumber const& phoneNumber)
{
  auto const body = nlohmann::json({{"phone_number", phoneNumber},
                                    {"app_id", appId},
                                    {"auth_token", verificationApiToken}});
  auto const message = body.dump();

  auto request = std::make_shared<tcurl::request>();
  request->set_url(fmt::format("{}/verification/sms/code", host_url));
  curl_easy_setopt(request->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(
      request->get_curl(), CURLOPT_POSTFIELDSIZE, long(message.size()));
  curl_easy_setopt(request->get_curl(), CURLOPT_COPYPOSTFIELDS, message.data());
  request->add_header("Content-type: application/json");

  tcurl::multi client;
  auto const response = TC_AWAIT(tcurl::read_all(client, request));
  long httpcode;
  curl_easy_getinfo(request->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
  if (httpcode != 200)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "could not retrieve verification code for {}",
                           phoneNumber);
  auto const jresponse =
      nlohmann::json::parse(response.data.begin(), response.data.end());
  TC_RETURN(jresponse.at("verification_code").get<std::string>());
}
}
