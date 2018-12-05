#pragma once

#include <cstdint>
#include <vector>

namespace Tanker
{
enum class IndexType
{
  UserId = 1,
  DevicePublicSignatureKey,
};

struct Index
{
  IndexType type;
  std::vector<uint8_t> value;
};
}
