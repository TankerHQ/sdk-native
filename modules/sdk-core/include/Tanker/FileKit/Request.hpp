#pragma once

#include <Tanker/CloudStorage.hpp>
#include <tccurl/curl.hpp>
#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

#include <string>

namespace Tanker
{
namespace FileKit
{
tc::cotask<std::string> getUploadUrl(tccurl::multi& multi,
                                     CloudStorage::UploadTicket const& ticket,
                                     std::string const& encryptedMetadata);

tc::cotask<void> performUploadRequest(tccurl::multi& multi,
                                      std::string const& url,
                                      uint64_t position,
                                      bool endOfStream,
                                      gsl::span<uint8_t const> data);

tc::cotask<std::string> downloadMetadata(
    tccurl::multi& multi,
    Trustchain::ResourceId const& resourceId,
    std::string const& url);
}
}
