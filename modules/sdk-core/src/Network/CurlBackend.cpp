#include <Tanker/Network/CurlBackend.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>

#include <fmt/ostream.h>

TLOG_CATEGORY(CurlBackend);

namespace Tanker::Network
{
namespace
{
std::shared_ptr<tcurl::request> makeRequest(SdkInfo sdkInfo, HttpRequest const& req)
{
  auto creq = std::make_shared<tcurl::request>();
  creq->set_url(std::move(req.url));

  switch (req.method)
  {
  case HttpMethod::Get:
    break;
  case HttpMethod::Put:
    curl_easy_setopt(creq->get_curl(), CURLOPT_CUSTOMREQUEST, "PUT");
    break;
  case HttpMethod::Post:
    curl_easy_setopt(creq->get_curl(), CURLOPT_CUSTOMREQUEST, "POST");
    break;
  case HttpMethod::Patch:
    curl_easy_setopt(creq->get_curl(), CURLOPT_CUSTOMREQUEST, "PATCH");
    break;
  case HttpMethod::Delete:
    curl_easy_setopt(creq->get_curl(), CURLOPT_CUSTOMREQUEST, "DELETE");
    break;
  }
  if (!req.body.empty())
  {
    curl_easy_setopt(creq->get_curl(), CURLOPT_POSTFIELDSIZE, long(req.body.size()));
    curl_easy_setopt(creq->get_curl(), CURLOPT_COPYPOSTFIELDS, req.body.data());
  }
  else
  {
    creq->add_header("Content-Length: 0");
  }

  for (auto const& [name, value] : req.headers)
    creq->add_header(fmt::format("{}: {}", name, value));

  return creq;
}
}

CurlBackend::CurlBackend(SdkInfo sdkInfo, std::chrono::nanoseconds timeout) : _sdkInfo(std::move(sdkInfo))
{
}

tc::cotask<HttpResponse> CurlBackend::fetch(HttpRequest req)
{
  try
  {
    auto creq = makeRequest(_sdkInfo, req);
    auto const cres = TC_AWAIT(tcurl::read_all(_cl, creq));

    HttpResponse res;
    long httpcode;
    curl_easy_getinfo(creq->get_curl(), CURLINFO_RESPONSE_CODE, &httpcode);
    res.statusCode = httpcode;

    struct curl_header* prev = NULL;
    struct curl_header* h;
    int last_request = -1;
    // All headers except HTTP 2/3 pseudo-headers and CONNECT proxy responses
    unsigned int header_types = CURLH_HEADER | CURLH_1XX | CURLH_TRAILER;
    while ((h = curl_easy_nextheader(creq->get_curl(), header_types, last_request, prev)))
    {
      res.headers.append(h->name, h->value);
      prev = h;
    }

    res.body = std::string(cres.data.begin(), cres.data.end());
    TC_RETURN(res);
  }
  catch (tcurl::exception const& e)
  {
    throw Errors::formatEx(Errors::Errc::NetworkError, "{}", e.what());
  }
}
}
