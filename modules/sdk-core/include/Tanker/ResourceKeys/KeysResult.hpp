#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tuple>
#include <vector>

namespace Tanker::ResourceKeys
{
struct KeyResult
{
  Crypto::SymmetricKey key;
  Trustchain::ResourceId resourceId;
};

bool operator==(KeyResult const& lhs, KeyResult const& rhs);
bool operator!=(KeyResult const& lhs, KeyResult const& rhs);

using KeysResult = std::vector<KeyResult>;
}
