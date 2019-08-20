#include <Tanker/FileKit/Request.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

namespace Tanker
{
namespace FileKit
{
tc::cotask<std::string> getUploadUrl(tccurl::multi& multi,
                                     CloudStorage::UploadTicket const& ticket,
                                     std::string const& encryptedMetadata)
{
  auto const req = std::make_shared<tccurl::request>();
  req->set_url(ticket.url);
  for (auto const header : ticket.headers)
    req->add_header(fmt::format("{}: {}", header.first, header.second));
  req->add_header(
      fmt::format("x-goog-meta-tanker-metadata: {}", encryptedMetadata));
  req->add_header("content-type:");
  curl_easy_setopt(req->get_curl(), CURLOPT_POST, 1L);
  curl_easy_setopt(req->get_curl(), CURLOPT_POSTFIELDSIZE, 0L);

  auto const result = TC_AWAIT(tccurl::read_all(multi, req));
  if (!req->is_response_ok())
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status for initial upload request: {}: {}",
                           req->get_status_code(),
                           std::string(result.data.begin(), result.data.end()));
  TC_RETURN(result.header.at("location"));
}

tc::cotask<void> performUploadRequest(tccurl::multi& multi,
                                      std::string const& url,
                                      uint64_t position,
                                      bool endOfStream,
                                      gsl::span<uint8_t const> data)
{
  auto const req = std::make_shared<tccurl::request>();
  req->set_url(url);

  // Use CUSTOMREQUEST and not PUT or UPLOAD. This avoids an "Expect:
  // 100-continue" roundtrip and makes use of POSTFIELDS instead of READDATA.
  curl_easy_setopt(req->get_curl(), CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(req->get_curl(), CURLOPT_POSTFIELDS, data.data());
  curl_easy_setopt(
      req->get_curl(), CURLOPT_POSTFIELDSIZE, static_cast<long>(data.size()));
  auto const fullSize =
      endOfStream ? std::to_string(position + data.size()) : "*";
  req->add_header(fmt::format("content-range: bytes {}-{}/{}",
                              position,
                              position + data.size() - 1,
                              fullSize));
  auto const result = TC_AWAIT(tccurl::read_all(multi, req));
  if ((endOfStream && req->get_status_code() != 200) ||
      (!endOfStream && req->get_status_code() != 308))
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status code for upload request: {}: {}",
                           req->get_status_code(),
                           std::string(result.data.begin(), result.data.end()));
}

tc::cotask<std::string> downloadMetadata(
    tccurl::multi& multi,
    Trustchain::ResourceId const& resourceId,
    std::string const& url)
{
  auto const req = std::make_shared<tccurl::request>();
  req->set_url(url);
  curl_easy_setopt(req->get_curl(), CURLOPT_NOBODY, 1L);

  auto const result = TC_AWAIT(tccurl::read_all(multi, req));
  if (req->get_status_code() == 404)
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        "could not find a file with the following resource ID: {}",
        resourceId);
  if (!req->is_response_ok())
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status for download HEAD request: {}",
                           req->get_status_code());
  TC_RETURN(result.header.at("x-goog-meta-tanker-metadata"));
}
}
}
