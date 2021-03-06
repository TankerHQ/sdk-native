#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>

#include <string>

namespace Tanker
{
struct SdkInfo
{
  std::string sdkType;
  Trustchain::TrustchainId trustchainId;
  std::string version;
};
}
