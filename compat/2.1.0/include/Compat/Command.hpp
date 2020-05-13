#pragma once

#include <Tanker/Test/Functional/Trustchain.hpp>
#include <Tanker/Test/Functional/TrustchainFactory.hpp>

#include <memory>
#include <string>

namespace Tanker
{
namespace Compat
{
class Command
{
public:
  Command(Test::Trustchain& tc,
          std::string tankerPath,
          std::string statePath,
          std::string bobCode)
    : tankerPath(std::move(tankerPath)),
      statePath(std::move(statePath)),
      trustchain(tc),
      bobCode(std::move(bobCode))
  {
  }

  virtual void base() = 0;
  virtual void next() = 0;
  virtual ~Command() = default;

protected:
  static constexpr auto bobEmail = "bob@tanker.io";

  std::string tankerPath;
  std::string statePath;
  std::string bobCode;
  Test::Trustchain& trustchain;
};

using CreateFn = std::function<std::unique_ptr<Command>(Test::Trustchain& tc,
                                                        std::string tankerPath,
                                                        std::string satePate,
                                                        std::string bobCode)>;

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
                  [](Tanker::Test::Trustchain& tc,
                     std::string tankerPath,
                     std::string statePath,
                     std::string bobCode) {
                    return std::make_unique<C>(tc,
                                               std::move(tankerPath),
                                               std::move(statePath),
                                               std::move(bobCode));
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
