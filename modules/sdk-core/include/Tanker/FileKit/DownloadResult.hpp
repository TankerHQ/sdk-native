#pragma once
#include <Tanker/FileKit/Metadata.hpp>
#include <Tanker/Streams/InputSource.hpp>

#include <vector>

namespace Tanker
{
namespace FileKit
{
struct DownloadResult
{
  std::vector<uint8_t> data;
  Metadata metadata;
};

struct DownloadStreamResult
{
  Streams::InputSource stream;
  Metadata metadata;
};
}
}
