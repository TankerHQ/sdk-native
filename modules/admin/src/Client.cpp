#include <Tanker/Admin/Client.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>

#include <fetchpp/fetch.hpp>
#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/request.hpp>

#include <fetchpp/alias/http.hpp>

#include <tconcurrent/asio_use_future.hpp>

#include <chrono>

TLOG_CATEGORY(Admin);

namespace Tanker::Admin
{
using namespace fetchpp::http;

using Tanker::Trustchain::Actions::Nature;
using namespace Tanker::Errors;

namespace
{
struct ServerErrorMessage
{
  std::string code;
  fetchpp::http::status status;
  std::string message;
  std::string requestId;
};

void from_json(nlohmann::json const& j, ServerErrorMessage& msg)
{
  j.at("code").get_to(msg.code);
  msg.status = fetchpp::http::int_to_status(j.at("status").get<int>());
  j.at("message").get_to(msg.message);
  j.at("trace_id").get_to(msg.requestId);
}

auto errorReport(Errors::AppdErrc err_code,
                 std::string_view customMessage,
                 fetchpp::http::response const& response)
{
  try
  {
    auto const serverMsg =
        response.json().at("error").get<ServerErrorMessage>();
    return Errors::formatEx(err_code,
                            "{}: {} {}",
                            customMessage,
                            serverMsg.code,
                            serverMsg.message);
  }
  catch (...)
  {
    return Errors::formatEx(
        err_code, "{}: invalid error: {}", customMessage, response.text());
  }
}
}
void from_json(nlohmann::json const& j, App& app)
{
  j.at("id").get_to(app.id);
  j.at("auth_token").get_to(app.authToken);
  if (auto value = j.at("oidc_client_id").get<std::string>(); !value.empty())
    app.oidcClientId = value;
  if (auto value = j.at("oidc_provider").get<std::string>(); !value.empty())
    app.oidcProvider = value;
}

Client::Client(std::string_view host_url,
               std::string_view idToken,
               fetchpp::net::executor ex)
  : _baseUrl("/apps", fetchpp::http::url(host_url)),
    _idToken{idToken},
    _client(ex, std::chrono::seconds(10), Cacerts::create_ssl_context())
{
}

void Client::setIdToken(std::string_view idToken)
{
  _idToken = idToken;
}

fetchpp::http::url Client::make_url(
    std::optional<Trustchain::TrustchainId> id) const
{
  using fetchpp::http::url;
  if (id)
    return url(fmt::format("/apps/{:#S}", id.value()), _baseUrl);
  return _baseUrl;
}

tc::cotask<App> Client::createTrustchain(
    std::string_view name, Crypto::SignatureKeyPair const& keyPair, bool isTest)
{
  auto request =
      fetchpp::http::request(verb::get, url("/environments", _baseUrl));
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  auto const response =
      TC_AWAIT(_client.async_fetch(std::move(request), tc::asio::use_future));
  if (response.result() != status::ok)
    throw errorReport(Errors::AppdErrc::InternalError,
                      "could not get environments",
                      response);
  auto const envs = response.json().at("environments");
  if (envs.empty())
    throw errorReport(
        Errors::AppdErrc::InternalError, "environment list is empty", response);

  auto env_id = envs[0].at("id").get<std::string>();
  TC_RETURN(TC_AWAIT(createTrustchain(name, keyPair, env_id, isTest)));
}

tc::cotask<App> Client::createTrustchain(
    std::string_view name,
    Crypto::SignatureKeyPair const& keyPair,
    std::string_view environmentId,
    bool isTest)
{
  using namespace Tanker::Trustchain;
  Actions::TrustchainCreation const action(keyPair.publicKey);
  TrustchainId const trustchainId{action.hash()};

  auto message = nlohmann::json{
      {"name", name},
      {"root_block", mgs::base64::encode(Serialization::serialize(action))},
      {"environment_id", environmentId},
  };
  if (isTest)
    message["private_signature_key"] = keyPair.privateKey;

  auto request = fetchpp::http::request(verb::post, make_url());
  request.content(message.dump());
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  TINFO("creating trustchain {} {:#S} on environment ",
        name,
        trustchainId,
        environmentId);

  auto const response =
      TC_AWAIT(_client.async_fetch(std::move(request), tc::asio::use_future));
  if (response.result() == status::created)
    TC_RETURN(response.json().at("app"));
  throw errorReport(
      Errors::AppdErrc::InternalError, "could not create trustchain", response);
}

tc::cotask<void> Client::deleteTrustchain(
    Trustchain::TrustchainId const& trustchainId)
{
  auto request = fetchpp::http::request(fetchpp::http::verb::delete_,
                                        make_url(trustchainId));
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  TINFO("deleting trustchain {:#S}", trustchainId);
  auto response =
      TC_AWAIT(_client.async_fetch(std::move(request), tc::asio::use_future));
  if (response.result() == status::ok)
    TC_RETURN();
  throw errorReport(
      Errors::AppdErrc::InternalError, "could not delete trustchain", response);
}

tc::cotask<App> Client::update(Trustchain::TrustchainId const& trustchainId,
                               AppUpdateOptions const& options)
{
  TINFO("updating trustchain {:#S}", trustchainId);
  auto body = nlohmann::json{};
  if (options.oidcClientId)
    body["oidc_client_id"] = *options.oidcClientId;
  if (options.oidcProvider)
    body["oidc_provider"] = *options.oidcProvider;
  if (options.sessionCertificates)
    body["session_certificates_enabled"] = *options.sessionCertificates;
  auto request = fetchpp::http::request(verb::patch, make_url(trustchainId));
  request.content(body.dump());
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  auto const response =
      TC_AWAIT(_client.async_fetch(std::move(request), tc::asio::use_future));
  if (response.result() == status::ok)
    TC_RETURN(response.json().at("app"));

  throw errorReport(
      Errors::AppdErrc::InternalError, "could not update trustchain", response);
}

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view host_url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& authToken,
    Email const& email)
{
  auto const body = nlohmann::json(
      {{"email", email}, {"app_id", appId}, {"auth_token", authToken}});
  auto req = fetchpp::http::request(
      verb::post, url("/verification/email/code", url(host_url)));
  req.content(body.dump());
  req.set(field::accept, "application/json");
  auto const response = TC_AWAIT(fetchpp::async_fetch(
      tc::get_default_executor().get_io_service().get_executor(),
      std::move(req),
      tc::asio::use_future));
  if (response.result() != status::ok)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "could not retrieve verification code for {}",
                           email);
  TC_RETURN(response.json().at("verification_code").get<std::string>());
}

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view host_url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& authToken,
    PhoneNumber const& phoneNumber)
{
  auto const body = nlohmann::json({{"phone_number", phoneNumber},
                                    {"app_id", appId},
                                    {"auth_token", authToken}});
  auto req = fetchpp::http::request(
      verb::post, url("/verification/sms/code", url(host_url)));
  req.content(body.dump());
  req.set(field::accept, "application/json");
  auto const response = TC_AWAIT(fetchpp::async_fetch(
      tc::get_default_executor().get_io_service().get_executor(),
      std::move(req),
      tc::asio::use_future));
  if (response.result() != status::ok)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "could not retrieve verification code for {}",
                           phoneNumber);
  TC_RETURN(response.json().at("verification_code").get<std::string>());
}
}
