#include <fstream>
#include <iostream>
#include <sstream>

#include <cppcodec/hex_lower.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <Tanker/UserToken/UserToken.hpp>

#include <docopt/docopt.h>

#include <tconcurrent/coroutine.hpp>

using namespace Tanker;

static constexpr auto TrustchainPrivateKeyOpt = "--trustchain-private-key";
static constexpr auto UserTokenOpt = "--user-token";
static constexpr auto UnlockKeyOpt = "--unlock-key";
static constexpr auto UnlockPasswordOpt = "--unlock-password";

static const char USAGE[] =
    R"(Tanker CLI

    Usage:
      tcli deserializeblock [-x] <block>
      tcli deserializesplitblock [-x] <index> <nature> <payload> <author> <signature>
      tcli createusertoken <trustchainid> <userid> --trustchain-private-key=<trustchainprivatekey>
      tcli open <trustchainurl> <trustchainid> (--user-token=<usertoken>|--trustchain-private-key=<trustchainprivatekey>) [--unlock-key=<unlockkey>] [--unlock-password=<unlockpassword>] <userid>
      tcli encrypt <trustchainurl> <trustchainid> [--trustchain-private-key=<trustchainprivatekey>] <userid> <cleartext> [--share=<shareto>]
      tcli decrypt <trustchainurl> <trustchainid> [--trustchain-private-key=<trustchainprivatekey>] <userid> <encrypteddata>
      tcli --help

    Options:
      -h --help     Show this screen.
      -x --hex      Input is in hex (default: b64)
)";

using MainArgs = std::map<std::string, docopt::value>;

namespace
{
std::string formatEntry(Block const& block, UnverifiedEntry const& entry)
{
  nlohmann::json jblock(block);
  nlohmann::json jentry(entry);

  auto merged = jblock;
  merged.insert(jentry.begin(), jentry.end());
  return merged.dump(4);
}

std::string readfile(std::string const& file)
{
  std::ifstream in(file);
  std::ostringstream sstr;
  sstr << in.rdbuf();
  return sstr.str();
}

void writefile(std::string const& file, std::string const& data)
{
  std::ofstream in(file, std::ios::out | std::ios::trunc);
  in.write(data.data(), data.size());
}

struct AsyncCoreDeleter
{
  void operator()(AsyncCore* c) const
  {
    c->destroy().get();
  }
};

using AsyncCorePtr = std::unique_ptr<AsyncCore, AsyncCoreDeleter>;

std::string createUserToken(MainArgs const& args)
{
  auto const trustchainId = args.at("<trustchainid>").asString();
  auto const userId = args.at("<userid>").asString();
  return Tanker::UserToken::generateUserToken(
      trustchainId,
      args.at(TrustchainPrivateKeyOpt).asString(),
      Tanker::SUserId{userId});
}

AsyncCorePtr openTanker(MainArgs const& args)
{
  auto const trustchainId = args.at("<trustchainid>").asString();
  auto const userId = args.at("<userid>").asString();

  auto const userTokenFile = userId + ".usertoken";

  auto const savedUserToken = readfile(userTokenFile);

  auto const userToken = [&] {
    if (args.at(UserTokenOpt))
      return args.at(UserTokenOpt).asString();
    else if (!savedUserToken.empty())
      return savedUserToken;
    else
      return Tanker::UserToken::generateUserToken(
          trustchainId,
          args.at(TrustchainPrivateKeyOpt).asString(),
          Tanker::SUserId{userId});
  }();

  writefile(userTokenFile, userToken);

  auto core = AsyncCorePtr{new AsyncCore(args.at("<trustchainid>").asString(),
                                         args.at("<trustchainurl>").asString(),
                                         ".")};

  auto const connection =
      core->connectEvent(Event::UnlockRequired, [&](void*, void*) {
        tc::async_resumable([&]() -> tc::cotask<void> {
          try
          {
            if (args.at(UnlockKeyOpt))
            {
              auto const unlockKey = args.at(UnlockKeyOpt).asString();
              TC_AWAIT(core->unlockCurrentDevice(UnlockKey{unlockKey}));
            }
            else if (args.at(UnlockPasswordOpt))
            {
              auto const unlockPassword = args.at(UnlockPasswordOpt).asString();
              TC_AWAIT(core->unlockCurrentDevice(Password{unlockPassword}));
            }
            else
              throw std::runtime_error(
                  "Unlock required but no unlock key, nor unlock password "
                  "provided");
          }
          catch (std::exception const& e)
          {
            std::cout << "Failed to unlock: " << e.what() << std::endl;
            core->close();
          }
        });
      });

  core->open(Tanker::SUserId{args.at("<userid>").asString()}, userToken).get();
  core->syncTrustchain().get();
  return core;
}
}

int main(int argc, char* argv[])
{
  std::map<std::string, docopt::value> args =
      docopt::docopt(USAGE,
                     {argv + 1, argv + argc},
                     true,        // show help if requested
                     "tcli 0.1"); // version string

  if (args.at("deserializeblock").asBool())
  {
    Block block;

    if (args.at("--hex").asBool())
      block = Serialization::deserialize<Block>(
          cppcodec::hex_lower::decode(args.at("<block>").asString()));
    else
      block = Serialization::deserialize<Block>(
          base64::decode(args.at("<block>").asString()));

    auto const entry = blockToUnverifiedEntry(block);
    std::cout << formatEntry(block, entry) << std::endl;
  }
  else if (args.at("deserializesplitblock").asBool())
  {
    Block block;

    block.index = args.at("<index>").asLong();
    block.nature = static_cast<Nature>(args.at("<nature>").asLong());
    if (args.at("--hex").asBool())
    {
      block.payload =
          cppcodec::hex_lower::decode(args.at("<payload>").asString());
      block.author =
          cppcodec::hex_lower::decode(args.at("<author>").asString());
      block.signature =
          cppcodec::hex_lower::decode(args.at("<signature>").asString());
    }
    else
    {
      block.payload = base64::decode(args.at("<payload>").asString());
      block.author = base64::decode(args.at("<author>").asString());
      block.signature = base64::decode(args.at("<signature>").asString());
    }

    auto const entry = blockToUnverifiedEntry(block);
    std::cout << formatEntry(block, entry) << std::endl;
  }
  else if (args.at("open").asBool())
  {
    auto const core = openTanker(args);
  }
  else if (args.at("createusertoken").asBool())
  {
    std::cout << createUserToken(args) << std::endl;
  }
  else if (args.at("encrypt").asBool())
  {
    auto const core = openTanker(args);

    std::vector<Tanker::SUserId> shareTo;
    if (args.at("--share"))
      shareTo.push_back(SUserId{args.at("--share").asString()});

    auto const cleartext = args.at("<cleartext>").asString();
    std::vector<uint8_t> encrypted(AsyncCore::encryptedSize(cleartext.size()));

    core->encrypt(encrypted.data(),
                  gsl::make_span(cleartext).as_span<uint8_t const>(),
                  shareTo)
        .get();
    fmt::print("encrypted: {}\n", base64::encode(encrypted));
  }
  else if (args.at("decrypt").asBool())
  {
    auto const core = openTanker(args);

    auto const encrypteddata =
        base64::decode(args.at("<encrypteddata>").asString());
    std::vector<uint8_t> decrypted(
        AsyncCore::decryptedSize(encrypteddata).get());

    core->decrypt(decrypted.data(),
                  gsl::make_span(encrypteddata).as_span<uint8_t const>())
        .get();
    fmt::print(
        "decrypted: {}\n",
        std::string(decrypted.data(), decrypted.data() + decrypted.size()));
  }

  return 0;
}
