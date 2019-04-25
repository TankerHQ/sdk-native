#pragma once

#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>

namespace Tanker
{
struct Block;

struct UnverifiedEntry
{
  uint64_t index;
  Trustchain::Actions::Nature nature;
  Crypto::Hash author;
  Trustchain::Action action;
  Crypto::Signature signature;
  Crypto::Hash hash;
};

bool operator==(UnverifiedEntry const& l, UnverifiedEntry const& r);
bool operator!=(UnverifiedEntry const& l, UnverifiedEntry const& r);

void to_json(nlohmann::json& j, UnverifiedEntry const& e);

UnverifiedEntry blockToUnverifiedEntry(Block const& block);
}
