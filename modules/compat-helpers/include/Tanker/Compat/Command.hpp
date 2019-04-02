#pragma once

#include "Trustchain.hpp"

#include <string>

namespace Tanker
{
namespace Compat
{
class Command
{
public:
  Command(Compat::Trustchain::Ptr tc,
          std::string tankerPath,
          std::string statePath)
    : tankerPath(std::move(tankerPath)),
      statePath(std::move(statePath)),
      trustchain(std::move(tc))
  {
  }
  virtual void base() = 0;
  virtual void next() = 0;
  virtual ~Command() = default;

protected:
  std::string tankerPath;
  std::string statePath;
  Compat::Trustchain::Ptr trustchain;
};
}
}
