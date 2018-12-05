#include <Tanker/Entry.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

using namespace std::string_literals;

namespace Tanker
{
bool operator==(Entry const& l, Entry const& r)
{
  return std::tie(l.index, l.author, l.action, l.hash) ==
         std::tie(r.index, r.author, r.action, r.hash);
}

bool operator!=(Entry const& l, Entry const& r)
{
  return !(l == r);
}

void to_json(nlohmann::json& j, Entry const& e)
{
  j["index"] = e.index;
  j["nature"] = e.nature;
  j["author"] = e.author;
  j["action_type"] = e.action.nature();
  j["action"] = e.action;
  j["hash"] = e.hash;
}
}
