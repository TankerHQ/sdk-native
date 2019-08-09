#pragma once

#include <Tanker/AsyncCore.hpp>
#include <Tanker/StreamInputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tccurl/curl.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstdint>
#include <utility>

namespace Tanker
{
namespace FileKit
{
struct Metadata
{
  nonstd::optional<std::string> mime;
  nonstd::optional<std::string> name;
  nonstd::optional<std::chrono::milliseconds> lastModified;
};

void from_json(nlohmann::json const& j, Metadata& m);
void to_json(nlohmann::json& j, Metadata const& m);

class FileKit
{
public:
  FileKit(AsyncCore& core);

  tc::cotask<Trustchain::ResourceId> upload(
      gsl::span<uint8_t const> data,
      Metadata const& metadata = {},
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});
  tc::cotask<Trustchain::ResourceId> uploadStream(
      StreamInputSource data,
      uint64_t size,
      Metadata const& metadata = {},
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});
  tc::cotask<std::pair<std::vector<uint8_t>, Metadata>> download(
      Trustchain::ResourceId const& resourceId);

private:
  AsyncCore& _core;

  tccurl::multi multi;

  tc::cotask<std::string> encryptMetadata(
      Metadata const& metadata,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});
  tc::cotask<std::string> getUploadUrl(CloudStorage::UploadTicket const& ticket,
                                       std::string const& encryptedMetadata);
  tc::cotask<void> performUploadRequest(std::string const& url,
                                        uint64_t position,
                                        bool endOfStream,
                                        gsl::span<uint8_t const> data);

  tc::cotask<std::string> downloadMetadata(
      Trustchain::ResourceId const& resourceId, std::string const& url);
  tc::cotask<Metadata> decryptMetadata(std::string const& sencryptedMetadata);
  tc::cotask<std::vector<uint8_t>> performDownloadRequest(
      std::string const& url);
};
}
}
