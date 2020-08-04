#pragma once

#include <cstdint>

namespace Tanker::Log
{
enum class Level : std::uint8_t
{
  Debug = 1,
  Info,
  Warning,
  Error,
};

}