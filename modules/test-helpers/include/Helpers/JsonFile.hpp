#pragma once

#include <nlohmann/json_fwd.hpp>
#include <string>

namespace Tanker
{
nlohmann::json loadJson(std::string const& src);

void saveJson(std::string const& dest, nlohmann::json const& json);
}
