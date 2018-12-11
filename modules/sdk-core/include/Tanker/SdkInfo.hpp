#pragma once

#include <Tanker/Types/TrustchainId.hpp>

#include <string>

namespace Tanker
{
struct SdkInfo
{
  std::string sdkType;
  TrustchainId trustchainId;
  std::string version;
};
}
