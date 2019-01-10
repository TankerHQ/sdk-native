#pragma once

#include <nlohmann/json_fwd.hpp>

#include <string>

namespace Tanker
{
namespace TestConstants
{
void setConfig(std::string const& cfg, std::string const& env);
std::string const& trustchainUrl();
std::string const& idToken();
}
}
