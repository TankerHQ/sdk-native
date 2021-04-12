#include <Tanker/Network/FetchppBackend.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>

#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/proxy.hpp>
#include <fetchpp/http/request.hpp>
#include <fetchpp/http/response.hpp>

#include <tconcurrent/asio_use_future.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(FetchppBackend);

namespace http = fetchpp::http;

namespace Tanker::Network
{
namespace
{
fetchpp::http::verb toFetchppVerb(HttpVerb verb)
{
  switch (verb)
  {
  case HttpVerb::get:
    return fetchpp::http::verb::get;
  case HttpVerb::post:
    return fetchpp::http::verb::post;
  case HttpVerb::put:
    return fetchpp::http::verb::put;
  case HttpVerb::patch:
    return fetchpp::http::verb::patch;
  case HttpVerb::delete_:
    return fetchpp::http::verb::delete_;
  default:
    throw Errors::AssertionError("unknown HTTP verb");
  }
}
}

FetchppBackend::FetchppBackend(SdkInfo sdkInfo,
                               std::chrono::nanoseconds timeout)
  : _cl(tc::get_default_executor().get_io_service().get_executor(),
        timeout,
        Cacerts::create_ssl_context()),
    _sdkInfo(std::move(sdkInfo))
{
  auto proxies = fetchpp::http::proxy_from_environment();
  if (auto proxyIt = proxies.find(http::proxy_scheme::https);
      proxyIt != proxies.end())
    TINFO("HTTPS proxy detected: {}", proxyIt->second.url());
  _cl.set_proxies(std::move(proxies));
}

FetchppBackend::~FetchppBackend() = default;

tc::cotask<HttpResponse> FetchppBackend::fetch(HttpRequest req)
{
  try
  {
    auto request = http::request(toFetchppVerb(req.verb), http::url(req.url));
    request.set("Accept", "application/json");
    request.set("X-Tanker-SdkType", _sdkInfo.sdkType);
    request.set("X-Tanker-SdkVersion", _sdkInfo.version);
    request.set("X-Tanker-Instanceid", req.instanceId);
    if (!req.authorization.empty())
      request.set(fetchpp::http::field::authorization, req.authorization);
    request.content(req.body);
    request.prepare_payload();
    auto const fResponse =
        TC_AWAIT(_cl.async_fetch(std::move(request), tc::asio::use_future));

    HttpResponse response;
    response.statusCode = fResponse.result_int();
    if (auto const contentType = fResponse.find(http::field::content_type);
        contentType != fResponse.end())
      response.contentType = contentType->value();
    response.body = fResponse.text();
    TC_RETURN(response);
  }
  catch (boost::system::system_error const& e)
  {
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "{}: {}",
                           e.code().category().name(),
                           e.code().message());
  }
}
}
