#include <Tanker/Admin/Client.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>

#include <fetchpp/fetch.hpp>
#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/json_body.hpp>
#include <fetchpp/http/request.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/string_body.hpp>
#include <fetchpp/alias/http.hpp>

#include <tconcurrent/asio_use_future.hpp>

TLOG_CATEGORY(Admin);

namespace Tanker::Admin
{
using namespace fetchpp::http;
using JsonRequest = fetchpp::http::request<fetchpp::http::json_body>;

using Tanker::Trustchain::Actions::Nature;
using namespace Tanker::Errors;

namespace
{
template <typename Request>
tc::future<fetchpp::http::response> execute(Request req)
{
  return fetchpp::async_fetch(tc::get_default_executor().get_io_service(),
                              Cacerts::get_ssl_context(),
                              std::move(req),
                              tc::asio::use_future);
}

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

auto errorReport(Errors::ServerErrc err_code,
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

Client::Client(std::string_view url, std::string_view idToken)
  : _baseUrl(fetchpp::http::url::parse(fmt::format("{}/apps", url))),
    _idToken{idToken}
{
}

void Client::setIdToken(std::string_view idToken)
{
  _idToken = idToken;
}

fetchpp::http::url Client::url(std::optional<Trustchain::TrustchainId> id) const
{
  if (id)
  {
    auto ret = _baseUrl;
    ret.target(fmt::format(TFMT("/apps/{:#S}"), id.value()));
    return ret;
  }
  return _baseUrl;
}

tc::cotask<App> Client::createTrustchain(
    std::string_view name, Crypto::SignatureKeyPair const& keyPair, bool isTest)
{
  using namespace Tanker::Trustchain;
  Actions::TrustchainCreation const action(keyPair.publicKey);
  auto const serializedPayload = Serialization::serialize(action);
  auto const trustchainId = static_cast<TrustchainId>(
      computeHash(action.nature(), {}, serializedPayload));
  auto const entry = ClientEntry(trustchainId,
                                 {},
                                 Actions::Nature::TrustchainCreation,
                                 serializedPayload,
                                 Crypto::Hash{trustchainId},
                                 {});

  auto message = nlohmann::json{
      {"name", name},
      {"root_block",
       cppcodec::base64_rfc4648::encode(Serialization::serialize(entry))},
  };
  if (isTest)
    message["private_signature_key"] = keyPair.privateKey;

  auto request = fetchpp::http::make_request<JsonRequest>(
      verb::post, url(), {}, std::move(message));
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  TINFO("creating trustchain {} {:#S}", name, trustchainId);

  auto const response = TC_AWAIT(execute(std::move(request)));
  if (response.result() == status::created)
    TC_RETURN(response.json().at("app"));
  throw errorReport(Errors::ServerErrc::InternalError,
                    "could not delete trustchain",
                    response);
}

tc::cotask<void> Client::deleteTrustchain(
    Trustchain::TrustchainId const& trustchainId)
{
  auto request = fetchpp::http::make_request(fetchpp::http::verb::delete_,
                                             url(trustchainId));
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  TINFO("deleting trustchain {:#S}", trustchainId);
  auto response = TC_AWAIT(execute(std::move(request)));
  if (response.result() == status::ok)
    return;
  throw errorReport(Errors::ServerErrc::InternalError,
                    "could not delete trustchain",
                    response);
}

tc::cotask<App> Client::update(Trustchain::TrustchainId const& trustchainId,
                               std::optional<std::string_view> oidcClientId,
                               std::optional<std::string_view> oidcProvider)
{
  TINFO("updating trustchain {:#S}", trustchainId);
  // FIXME: is that still necesseray since we have in the url ?
  auto body = nlohmann::json{};
  if (oidcClientId)
    body["oidc_client_id"] = *oidcClientId;
  if (oidcProvider)
    body["oidc_provider"] = *oidcProvider;
  auto request = fetchpp::http::make_request<JsonRequest>(
      verb::patch, url(trustchainId), {}, std::move(body));
  request.set(authorization::bearer(_idToken));
  request.set(field::accept, "application/json");
  auto const response = TC_AWAIT(execute(std::move(request)));
  if (response.result() == status::ok)
    TC_RETURN(response.json().at("app"));

  throw errorReport(Errors::ServerErrc::InternalError,
                    "could not update trustchain",
                    response);
}

tc::cotask<VerificationCode> getVerificationCode(
    std::string_view url,
    Tanker::Trustchain::TrustchainId const& appId,
    std::string const& authToken,
    Email const& email)
{
  using namespace fetchpp::http;
  auto req = make_request<fetchpp::http::request<json_body>>(
      verb::post,
      url::parse(fmt::format("{}/verification/email/code", url)),
      {},
      nlohmann::json(
          {{"email", email}, {"app_id", appId}, {"auth_token", authToken}}));
  req.set(field::accept, "application/json");
  auto const response =
      TC_AWAIT(fetchpp::async_fetch(tc::get_default_executor().get_io_service(),
                                    Cacerts::get_ssl_context(),
                                    std::move(req),
                                    tc::asio::use_future));
  if (response.result() != status::ok)
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "could not retrieve verificaiton code for {}",
                           email);
  TC_RETURN(response.json().at("verification_code").get<std::string>());
}
}
