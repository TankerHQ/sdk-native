#pragma once

#include <Tanker/Action.hpp>
#include <Tanker/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>

namespace Tanker
{
struct Block;

struct UnverifiedEntry
{
  uint64_t index;
  Nature nature;
  Crypto::Hash author;
  Action action;
  Crypto::Signature signature;
  Crypto::Hash hash;
};

bool operator==(UnverifiedEntry const& l, UnverifiedEntry const& r);
bool operator!=(UnverifiedEntry const& l, UnverifiedEntry const& r);

void to_json(nlohmann::json& j, UnverifiedEntry const& e);

UnverifiedEntry blockToUnverifiedEntry(Block const& block);
}
