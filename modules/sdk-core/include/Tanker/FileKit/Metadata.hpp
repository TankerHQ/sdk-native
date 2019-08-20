#pragma once

#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>

#include <chrono>

namespace Tanker
{
namespace FileKit
{
struct Metadata
{
  nonstd::optional<std::string> mime;
  nonstd::optional<std::string> name;
  nonstd::optional<std::chrono::milliseconds> lastModified;
};

void from_json(nlohmann::json const& j, Metadata& m);
void to_json(nlohmann::json& j, Metadata const& m);
}
}
