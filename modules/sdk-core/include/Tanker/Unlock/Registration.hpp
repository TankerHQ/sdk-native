#pragma once

#include <Tanker/Types/VerificationKey.hpp>
#include <vector>

namespace Tanker
{
namespace Unlock
{
struct Registration
{
  std::vector<uint8_t> block;
  VerificationKey verificationKey;
};
}
}
