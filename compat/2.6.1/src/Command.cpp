#include <Compat/Command.hpp>

#include <fmt/format.h>

#include <vector>

namespace Tanker
{
namespace Compat
{
namespace
{
std::vector<CommandInfo> commandInfos;
}

void registerCommand(std::string name, std::string description, CreateFn fn)
{
  auto it = find_if(cbegin(commandInfos),
                    cend(commandInfos),
                    [&name](auto&& info) { return info.name == name; });
  if (it != end(commandInfos))
    throw std::runtime_error(fmt::format("duplicate command {}", name));
  commandInfos.push_back(
      {std::move(name), std::move(description), std::move(fn)});
}

CommandInfo const& getCommand(std::string const& name)
{
  auto it = find_if(cbegin(commandInfos),
                    cend(commandInfos),
                    [&name](auto&& info) { return info.name == name; });
  if (it == end(commandInfos))
    throw std::runtime_error(fmt::format("cannot find command {}", name));
  return *it;
}

std::vector<CommandInfo> const& getAllCommands()
{
  return commandInfos;
}
}
}
