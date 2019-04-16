#pragma once

#include <Tanker/Test/Functional/Trustchain.hpp>
#include <Tanker/Test/Functional/TrustchainFactory.hpp>

#include <string>

namespace Tanker
{
namespace Compat
{
class Command
{
public:
  Command(Test::Trustchain& tc, std::string tankerPath, std::string statePath)
    : tankerPath(std::move(tankerPath)),
      statePath(std::move(statePath)),
      trustchain(tc)
  {
  }
  virtual void base() = 0;
  virtual void next() = 0;
  virtual ~Command() = default;

protected:
  std::string tankerPath;
  std::string statePath;
  Test::Trustchain& trustchain;
};
}
}
