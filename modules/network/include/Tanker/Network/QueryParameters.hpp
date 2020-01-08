#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>

#include <optional>
#include <string>

namespace Tanker
{
namespace Network
{
struct QueryParameters
{
  std::string sdkType;
  std::optional<Trustchain::TrustchainId> trustchainId;
  std::optional<std::string> version;
  std::optional<std::string> context;
};
}
}
