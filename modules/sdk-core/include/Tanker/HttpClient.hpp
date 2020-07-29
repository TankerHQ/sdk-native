#pragma once

#include <Tanker/Network/SdkInfo.hpp>

#include <fetchpp/client.hpp>
#include <fetchpp/http/authorization.hpp>
#include <fetchpp/http/json_body.hpp>
#include <fetchpp/http/request.hpp>
#include <fetchpp/http/url.hpp>

#include <nlohmann/json_fwd.hpp>

#include <tconcurrent/coroutine.hpp>

#include <chrono>
#include <string_view>

namespace Tanker
{
class HttpClient
{
public:
  HttpClient(fetchpp::http::url const& baseUrl,
             Network::SdkInfo const& info,
             fetchpp::net::executor ex,
             std::chrono::nanoseconds timeout = std::chrono::seconds(30));
  HttpClient(HttpClient const&) = delete;
  HttpClient(HttpClient&&) = delete;
  HttpClient& operator=(HttpClient const&) = delete;
  HttpClient& operator=(HttpClient&&) = delete;

  ~HttpClient();

  tc::cotask<nlohmann::json> asyncGet(std::string_view target);
  tc::cotask<nlohmann::json> asyncPost(std::string_view target,
                                       nlohmann::json data);
  tc::cotask<nlohmann::json> asyncPost(std::string_view target);
  tc::cotask<nlohmann::json> asyncDelete(std::string_view target);

  void setAccessToken(fetchpp::http::authorization::methods const& m);

private:
  [[nodiscard]] fetchpp::http::url makeUrl(std::string_view target) const;

private:
  fetchpp::http::url _baseUrl;
  fetchpp::http::request_header<> _headers;
  fetchpp::client _cl;
};
}