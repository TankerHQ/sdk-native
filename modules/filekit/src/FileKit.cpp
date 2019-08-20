#include <Tanker/FileKit/FileKit.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/EncryptionFormat/EncryptorV4.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/FileKit/Constants.hpp>
#include <Tanker/FileKit/DownloadStream.hpp>
#include <Tanker/Retry.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <nlohmann/json.hpp>

#include <optional.hpp>

namespace Tanker
{
namespace FileKit
{

FileKit::FileKit(AsyncCore& core) : _core(core)
{
}

tc::cotask<Trustchain::ResourceId> FileKit::upload(
    gsl::span<uint8_t const> data,
    Metadata const& metadata,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  TC_RETURN(TC_AWAIT(uploadStream(bufferToInputSource(data),
                                  data.size(),
                                  metadata,
                                  publicIdentities,
                                  groupIds)));
}

tc::cotask<Trustchain::ResourceId> FileKit::uploadStream(
    StreamInputSource source,
    uint64_t size,
    Metadata const& metadata,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto const encryptedMetadata =
      TC_AWAIT(encryptMetadata(metadata, publicIdentities, groupIds));

  auto const encryptedStream =
      TC_AWAIT(_core.makeStreamEncryptor(source, publicIdentities, groupIds));
  auto const resourceId = encryptedStream.resourceId();

  auto const uploadTicket = TC_AWAIT(_core.getFileUploadTicket(
      resourceId, EncryptionFormat::EncryptorV4::encryptedSize(size)));

  if (uploadTicket.service != "GCS")
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "unsupported storage service: {}",
                           uploadTicket.service);

  auto const uploadUrl =
      TC_AWAIT(getUploadUrl(uploadTicket, encryptedMetadata));

  auto const inputStream = StreamInputSource(encryptedStream);
  std::vector<uint8_t> buf(CHUNK_SIZE);
  uint64_t position = 0;
  while (auto const readSize = TC_AWAIT(readStream(buf, inputStream)))
  {
    TC_AWAIT(retry(
        [&]() -> tc::cotask<void> {
          TC_AWAIT(
              performUploadRequest(uploadUrl,
                                   position,
                                   static_cast<uint64_t>(readSize) < buf.size(),
                                   gsl::make_span(buf).subspan(0, readSize)));
        },
        exponentialDelays(2)));
    position += readSize;
  }

  TC_RETURN(resourceId);
}

tc::cotask<std::string> FileKit::encryptMetadata(
    Metadata const& metadata,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto const jmetadata = nlohmann::json(metadata).dump();
  auto const encryptedMetadata =
      TC_AWAIT(_core.encrypt(gsl::make_span(jmetadata).as_span<uint8_t const>(),
                             publicIdentities,
                             groupIds));
  TC_RETURN(cppcodec::base64_rfc4648::encode(encryptedMetadata));
}

tc::cotask<std::string> FileKit::getUploadUrl(
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

tc::cotask<void> FileKit::performUploadRequest(std::string const& url,
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

tc::cotask<DownloadResult> FileKit::download(
    Trustchain::ResourceId const& resourceId)
{
  auto const dlresult = TC_AWAIT(downloadStream(resourceId));
  std::vector<uint8_t> ret;
  std::vector<uint8_t> buf(CHUNK_SIZE);
  while (auto const readSize =
             TC_AWAIT(dlresult.stream(buf.data(), buf.size())))
    ret.insert(ret.end(), buf.begin(), buf.begin() + readSize);
  TC_RETURN((DownloadResult{std::move(ret), std::move(dlresult.metadata)}));
}

tc::cotask<DownloadStreamResult> FileKit::downloadStream(
    Trustchain::ResourceId const& resourceId)
{
  auto const downloadTicket = TC_AWAIT(_core.getFileDownloadTicket(resourceId));

  if (downloadTicket.service != "GCS")
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "unsupported storage service: {}",
                           downloadTicket.service);

  auto const metadata = TC_AWAIT(decryptMetadata(
      TC_AWAIT(downloadMetadata(resourceId, downloadTicket.url))));

  TC_RETURN(
      (DownloadStreamResult{TC_AWAIT(_core.makeStreamDecryptor(
                                DownloadStream(multi, downloadTicket.url))),
                            metadata}));
}

tc::cotask<std::string> FileKit::downloadMetadata(
    Trustchain::ResourceId const& resourceId, std::string const& url)
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

tc::cotask<Metadata> FileKit::decryptMetadata(
    std::string const& sencryptedMetadata)
{
  auto const encryptedMetadata =
      cppcodec::base64_rfc4648::decode(sencryptedMetadata);
  auto const decryptedMetadata = TC_AWAIT(_core.decrypt(encryptedMetadata));
  TC_RETURN(
      nlohmann::json::parse(decryptedMetadata.begin(), decryptedMetadata.end())
          .get<Metadata>());
}
}
}
