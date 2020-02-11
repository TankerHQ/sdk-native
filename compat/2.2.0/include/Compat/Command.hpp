#pragma once

#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>

#include <memory>
#include <string>

namespace Tanker
{
namespace Compat
{
class Command
{
public:
  Command(Functional::Trustchain& tc,
          std::string tankerPath,
          std::string statePath)
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
  Functional::Trustchain& trustchain;
};

using CreateFn = std::function<std::unique_ptr<Command>(
    Functional::Trustchain& tc, std::string tankerPath, std::string satePate)>;

struct CommandInfo
{
  std::string name;
  std::string description;
  CreateFn creator;
};

void registerCommand(std::string name, std::string description, CreateFn fn);

template <typename C>
bool registerCommand(std::string name, std::string description)
{
  registerCommand(std::move(name),
                  std::move(description),
                  [](Tanker::Functional::Trustchain& tc,
                     std::string tankerPath,
                     std::string statePath) {
                    return std::make_unique<C>(
                        tc, std::move(tankerPath), std::move(statePath));
                  });
  return true;
}

CommandInfo const& getCommand(std::string const& name);
std::vector<CommandInfo> const& getAllCommands();
}
}

#define REGISTER_CMD(TYPE, NAME, DESCRIPTION) \
  static auto reg_##TYPE =                    \
      Tanker::Compat::registerCommand<TYPE>(NAME, DESCRIPTION)
