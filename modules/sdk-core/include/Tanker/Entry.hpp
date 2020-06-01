#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>

namespace Tanker
{
struct Entry
{
  Trustchain::Actions::Nature nature;
  Crypto::Hash author;
  Trustchain::Action action;
  Crypto::Hash hash;
};

bool operator==(Entry const& l, Entry const& r);
bool operator!=(Entry const& l, Entry const& r);

void to_json(nlohmann::json& j, Entry const& e);
}
