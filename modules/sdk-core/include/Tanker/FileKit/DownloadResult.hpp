#pragma once
#include <Tanker/FileKit/Metadata.hpp>
#include <Tanker/StreamInputSource.hpp>

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
  StreamInputSource stream;
  Metadata metadata;
};
}
}
