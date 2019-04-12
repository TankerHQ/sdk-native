#pragma once

#include <Tanker/Action.hpp>
#include <Tanker/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>

namespace Tanker
{
struct Entry
{
  uint64_t index;
  Nature nature;
  Crypto::Hash author;
  Action action;
  Crypto::Hash hash;
};

bool operator==(Entry const& l, Entry const& r);
bool operator!=(Entry const& l, Entry const& r);

void to_json(nlohmann::json& j, Entry const& e);
}
