#pragma once

#include <Tanker/Types/UnlockKey.hpp>
#include <vector>

namespace Tanker
{
namespace Unlock
{
struct Registration
{
  std::vector<uint8_t> block;
  UnlockKey unlockKey;
};
}
}
