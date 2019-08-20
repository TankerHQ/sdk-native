#include <Tanker/FileKit/Metadata.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace FileKit
{
namespace
{
template <typename T>
nonstd::optional<T> getJsonOptional(nlohmann::json const& j,
                                    std::string const& name)
{
  auto it = j.find(name);
  if (it == j.end())
    return nonstd::nullopt;
  if (it->is_null())
    return nonstd::nullopt;
  return it->get<T>();
}
}
void from_json(nlohmann::json const& j, Metadata& m)
{
  m.mime = getJsonOptional<std::string>(j, "mime");
  m.name = getJsonOptional<std::string>(j, "name");
  auto const lastModified = getJsonOptional<uint64_t>(j, "lastModified");
  if (lastModified)
    m.lastModified = std::chrono::milliseconds(*lastModified);
}
void to_json(nlohmann::json& j, Metadata const& m)
{
  if (m.mime)
    j["mime"] = *m.mime;
  if (m.name)
    j["name"] = *m.name;
  if (m.lastModified)
    j["lastModified"] = m.lastModified->count();
}
}
}
