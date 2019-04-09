#include "Tests.hpp"
#include <Tanker/Test/Functional/TrustchainFactory.hpp>

#include <Tanker/Version.hpp>

#include <memory>

#include <docopt/docopt.h>

using namespace std::string_literals;
using Tanker::Test::Trustchain;
using Tanker::Test::TrustchainFactory;

static const char USAGE[] = R"(compat cli
  Usage:
    compat (encrypt|group|unlock) [--path=<basePath>] (--state=<statePath>) (--tc-temp-config=<trustchainPath>) (--base | --next) 

  Options:
    --path=<filePath>   directory path to store devices [default: /tmp]
    --state=<filePath>  file path to store/load serialized state
    (--base|--next)      use base or new code scenario

)";

auto getRunner = [](std::string const& command,
                    auto& trustchain,
                    std::string tankerPath,
                    std::string statePath) -> std::unique_ptr<Command> {
  if (command == "encrypt")
    return std::make_unique<EncryptCompat>(
        trustchain, std::move(tankerPath), std::move(statePath));
  else if (command == "group")
    return std::make_unique<GroupCompat>(
        trustchain, std::move(tankerPath), std::move(statePath));
  else if (command == "unlock")
    return std::make_unique<UnlockCompat>(
        trustchain, std::move(tankerPath), std::move(statePath));
  else
    throw std::runtime_error("not implemented");
};

auto getCommand = [](auto args) {
  if (args.at("encrypt").asBool())
    return "encrypt"s;
  else if (args.at("group").asBool())
    return "group"s;
  else if (args.at("unlock").asBool())
    return "unlock"s;
  else
    throw std::runtime_error("not implemented");
};

using CompatFixture = std::tuple<TrustchainFactory::Ptr, Trustchain::Ptr>;

tc::cotask<std::tuple<TrustchainFactory::Ptr, Trustchain::Ptr>> getTrustchain(
    std::string const& command, std::string const& path, bool create)
{
  auto tf = TC_AWAIT(Tanker::Test::TrustchainFactory::create());
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
  auto args =
      docopt::docopt(USAGE, {argv + 1, argv + argc}, true, TANKER_VERSION);

  auto const tankerPath = args.at("--path").asString();
  auto const statePath = args.at("--state").asString();
  auto const command = getCommand(args);

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
