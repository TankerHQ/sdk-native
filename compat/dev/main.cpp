#include "Tests.hpp"
#include <Tanker/Compat/TrustchainFactory.hpp>

#include <Tanker/Version.hpp>

#include <memory>

#include <docopt/docopt.h>
using namespace std::string_literals;

static const char USAGE[] = R"(compat cli
  Usage:
    compat (encrypt|group|unlock) [--path=<basePath>] (--state=<statePath>) (--tc-temp-config=<trustchainPath>) (--base | --next) 

  Options:
    --path=<filePath>   directory path to store devices [default: /tmp]
    --state=<filePath>  file path to store/load serialized state
    (--base|--next)      use base or new code scenario

)";

auto getRunner = [](std::string const& command,
                    auto trustchain,
                    std::string tankerPath,
                    std::string statePath) -> std::unique_ptr<Command> {
  if (command == "encrypt")
    return std::make_unique<EncryptCompat>(
        std::move(trustchain), std::move(tankerPath), std::move(statePath));
  else if (command == "group")
    return std::make_unique<GroupCompat>(
        std::move(trustchain), std::move(tankerPath), std::move(statePath));
  else if (command == "unlock")
    return std::make_unique<UnlockCompat>(
        std::move(trustchain), std::move(tankerPath), std::move(statePath));
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

auto getTrustchain(TrustchainFactory& tf,
                   std::string const& command,
                   std::string path,
                   bool create)
{
  if (create)
  {
    auto trustchain =
        tf.createTrustchain(
              fmt::format("compat-{}-{}", command, TANKER_VERSION), true)
            .get();
    tf.saveTrustchainConfig(path, trustchain->toConfig());
    return trustchain;
  }
  return tf.useTrustchain(path).get();
}

int main(int argc, char** argv)
{
  auto args =
      docopt::docopt(USAGE, {argv + 1, argv + argc}, true, TANKER_VERSION);

  auto const tankerPath = args.at("--path").asString();
  auto const statePath = args.at("--state").asString();
  auto const command = getCommand(args);

  auto trustchainFactory = TrustchainFactory::create().get();
  auto trustchain = getTrustchain(trustchainFactory,
                                  command,
                                  args.at("--tc-temp-config").asString(),
                                  args.at("--base").asBool());

  auto runner =
      getRunner(command, std::move(trustchain), tankerPath, statePath);
  if (args.at("--base").asBool())
    runner->base();
  else if (args.at("--next").asBool())
    runner->next();
}
