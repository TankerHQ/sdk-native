#pragma once

#include <Tanker/AsyncCore.hpp>
#include <Tanker/FileKit/DownloadResult.hpp>
#include <Tanker/FileKit/Metadata.hpp>
#include <Tanker/StreamInputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tccurl/curl.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <utility>

namespace Tanker
{
namespace FileKit
{
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
  tc::cotask<DownloadResult> download(Trustchain::ResourceId const& resourceId);
  tc::cotask<DownloadStreamResult> downloadStream(
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
};
}
}
