#include <Tanker/UnverifiedEntry.hpp>

#include <Tanker/Block.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
bool operator==(UnverifiedEntry const& l, UnverifiedEntry const& r)
{
  return std::tie(l.index, l.author, l.action, l.signature, l.hash) ==
         std::tie(r.index, r.author, r.action, r.signature, r.hash);
}

bool operator!=(UnverifiedEntry const& l, UnverifiedEntry const& r)
{
  return !(l == r);
}

void to_json(nlohmann::json& j, UnverifiedEntry const& e)
{
  j["index"] = e.index;
  j["nature"] = e.nature;
  j["author"] = e.author;
  j["action_type"] = e.action.nature();
  j["action"] = e.action;
  j["hash"] = e.hash;
  j["signature"] = e.signature;
}

UnverifiedEntry blockToUnverifiedEntry(Block const& block)
{
  UnverifiedEntry ret;
  ret.index = block.index;
  ret.nature = block.nature;
  ret.author = block.author;
  ret.action = deserializeAction(block.nature, block.payload);
  ret.signature = block.signature;
  ret.hash = block.hash();
  return ret;
}
}
