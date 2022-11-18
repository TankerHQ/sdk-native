#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

#include <tuple>
#include <vector>

namespace Tanker::ResourceKeys
{
struct KeyResult
{
  Crypto::SymmetricKey key;
  Crypto::SimpleResourceId id;
};

bool operator==(KeyResult const& lhs, KeyResult const& rhs);
bool operator!=(KeyResult const& lhs, KeyResult const& rhs);

using KeysResult = std::vector<KeyResult>;
}
