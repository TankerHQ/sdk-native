#include <Tanker/FakeAuthentication/FakeAuthentication.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>

#include <nlohmann/json.hpp>

#include <boost/algorithm/string/join.hpp>

#include <fmt/format.h>

TLOG_CATEGORY("FakeAuthentication");

using Tanker::Errors::Errc;

namespace Tanker
{
namespace FakeAuthentication
{
namespace
{
std::string escapeUrl(std::string const& url)
{
  // curl_escape is deprecated, but curl_easy_escape needs a curl easy which we
  // sometimes don't have. The documentation doesn't justify the need of a curl
  // easy or why the previous function was deprecated
  auto const escapedEmail = curl_escape(url.data(), url.size());
  std::string const ret = escapedEmail;
  curl_free(escapedEmail);
  return ret;
}
}

void from_json(nlohmann::json const& j, PrivateIdentity& result)
{
  j.at("private_permanent_identity").get_to(result.permanentIdentity);
  auto const prov = j.find("private_provisional_identity");
  if (prov != j.end() && !prov->is_null())
  {
    std::string p;
    prov->get_to(p);
    result.provisionalIdentity = p;
  }
}

FakeAuthentication::FakeAuthentication(std::string const& url,
                                       std::string const& appId)
  : _baseUrl(fmt::format("{}/apps/{}", url, escapeUrl(appId)))
{
}

tc::cotask<PrivateIdentity> FakeAuthentication::getPrivateIdentity(
    nonstd::optional<std::string> const& email)
{
  std::string url;
  if (email)
    url = fmt::format(
        "{}/private_identity?email={}", _baseUrl, escapeUrl(*email));
  else
    url = _baseUrl + "/disposable_private_identity";

  auto const req = std::make_shared<tccurl::request>();
  req->set_url(url);
  auto const response = TC_AWAIT(tccurl::read_all(_multi, req));

  if (!req->is_response_ok())
    throw Errors::formatEx(
        Errc::NetworkError,
        "Server error: {}",
        std::string(response.data.begin(), response.data.end()));

  TC_RETURN(nlohmann::json::parse(response.data.begin(), response.data.end())
                .get<PrivateIdentity>());
}

tc::cotask<std::vector<std::string>> FakeAuthentication::getPublicIdentities(
    std::vector<std::string> const& emails)
{
  auto const url = fmt::format("{}/public_identities?emails={}",
                               _baseUrl,
                               escapeUrl(boost::algorithm::join(emails, ",")));

  auto const req = std::make_shared<tccurl::request>();
  req->set_url(url);
  auto const response = TC_AWAIT(tccurl::read_all(_multi, req));

  if (!req->is_response_ok())
    throw Errors::formatEx(
        Errc::NetworkError,
        "Server error: {}",
        std::string(response.data.begin(), response.data.end()));

  auto const jresponse =
      nlohmann::json::parse(response.data.begin(), response.data.end());

  std::vector<std::string> ret;
  for (auto const& id : jresponse)
    ret.push_back(id.at("public_identity").get<std::string>());
  TC_RETURN(ret);
}
}
}
