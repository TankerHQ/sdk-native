#include <Compat/Command.hpp>

#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>

#include <Tanker/Version.hpp>

#include <fmt/format.h>
#include <memory>

#include <docopt/docopt.h>

using namespace std::string_literals;
using namespace std::literals::chrono_literals;
using Tanker::Functional::Trustchain;
using Tanker::Functional::TrustchainFactory;

static const char USAGE[] = R"(compat cli
  Usage:
    compat <command> [--path=<basePath>] (--state=<statePath>) (--tc-temp-config=<trustchainPath>) (--base | --next) 

  Commands:
{}

  Options:
    --path=<filePath>   directory path to store devices [default: /tmp]
    --state=<filePath>  file path to store/load serialized state
    (--base|--next)      use base or new code scenario

)";

auto getRunner(std::string const& command,
               Trustchain& trustchain,
               std::string tankerPath,
               std::string statePath)
{
  auto runner = Tanker::Compat::getCommand(command);
  return runner.creator(
      trustchain, std::move(tankerPath), std::move(statePath));
}

using CompatFixture = std::tuple<TrustchainFactory::Ptr, Trustchain::Ptr>;

tc::cotask<std::tuple<TrustchainFactory::Ptr, Trustchain::Ptr>> getTrustchain(
    std::string const& command, std::string const& path, bool create)
{
  auto tf = TC_AWAIT(Tanker::Functional::TrustchainFactory::create());
  if (create)
  {
    auto trustchain = TC_AWAIT(tf->createTrustchain(
        fmt::format("compat-{}-{}", command, TANKER_VERSION), true));
    tf->saveTrustchainConfig(path, trustchain->toConfig());
    TC_RETURN(std::make_tuple(std::move(tf), std::move(trustchain)));
  }
  TC_RETURN(std::make_tuple(std::move(tf),
                            std::move(TC_AWAIT(tf->useTrustchain(path)))));
}

int main(int argc, char** argv)
{
  Tanker::TimeoutTerminate tt(5min);
  std::vector<std::string> commands;
  for (auto const& info : Tanker::Compat::getAllCommands())
    commands.push_back(
        fmt::format("{}{}\t\t{}", "    ", info.name, info.description));
  auto usage = fmt::format(USAGE, fmt::join(commands, "\n"));
  auto args =
      docopt::docopt(usage, {argv + 1, argv + argc}, true, TANKER_VERSION);

  auto const tankerPath = args.at("--path").asString();
  auto const statePath = args.at("--state").asString();
  auto const command = args.at("<command>").asString();

  auto compatFixture =
      tc::async_resumable([&]() -> tc::cotask<std::tuple<TrustchainFactory::Ptr,
                                                         Trustchain::Ptr>> {
        TC_RETURN(TC_AWAIT(getTrustchain(command,
                                         args.at("--tc-temp-config").asString(),
                                         args.at("--base").asBool())));
      })
          .get();

  auto runner = getRunner(command,
                          *std::get<Trustchain::Ptr>(compatFixture),
                          tankerPath,
                          statePath);
  if (args.at("--base").asBool())
    runner->base();
  else if (args.at("--next").asBool())
  {
    runner->next();
    tc::async_resumable([&]() -> tc::cotask<void> {
      TC_AWAIT(
          std::get<TrustchainFactory::Ptr>(compatFixture)
              ->deleteTrustchain(std::get<Trustchain::Ptr>(compatFixture)->id));
    })
        .get();
  }
}
