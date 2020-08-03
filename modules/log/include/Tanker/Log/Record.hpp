#pragma once

#include <Tanker/Log/Level.hpp>

namespace Tanker::Log
{
struct Record
{
  char const* category;
  Level level;
  char const* file;
  std::uint32_t line;
  char const* message;
};

}