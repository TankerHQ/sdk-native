#include <fstream>
#include <iostream>
#include <sstream>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <docopt/docopt.h>

#include <tconcurrent/coroutine.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

static constexpr auto TrustchainPrivateKeyOpt = "--trustchain-private-key";
static constexpr auto IdentityOpt = "--identity";
static constexpr auto VerificationKeyOpt = "--verification-key";
static constexpr auto UnlockPasswordOpt = "--unlock-password";

static const char USAGE[] =
    R"(Tanker CLI

    Usage:
      tcli deserializeblock [-x] <block>
      tcli deserializesplitblock [-x] <index> <nature> <payload> <author> <signature>
      tcli createidentity <trustchainid> <userid> --trustchain-private-key=<trustchainprivatekey>
      tcli signup <trustchainurl> <trustchainid> (--identity=<identity>|--trustchain-private-key=<trustchainprivatekey>) [--unlock-password=<unlockpassword>] <userid>
      tcli signin <trustchainurl> <trustchainid> (--identity=<identity>|--trustchain-private-key=<trustchainprivatekey>) [--verification-key=<verificationkey>] [--unlock-password=<unlockpassword>] <userid>
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
std::string formatEntry(Block const& block, ServerEntry const& entry)
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

std::string createIdentity(MainArgs const& args)
{
  auto const trustchainId = args.at("<trustchainid>").asString();
  auto const userId = args.at("<userid>").asString();
  return Tanker::Identity::createIdentity(
      trustchainId,
      args.at(TrustchainPrivateKeyOpt).asString(),
      Tanker::SUserId{userId});
}

std::string loadIdentity(std::string const& trustchainId,
                         std::string const& userId,
                         MainArgs const& args)
{
  auto const identityFile = userId + ".identity";

  auto const savedIdentity = readfile(identityFile);

  auto const identity = [&] {
    if (args.at(IdentityOpt))
      return args.at(IdentityOpt).asString();
    else if (!savedIdentity.empty())
      return savedIdentity;
    else
      return Tanker::Identity::createIdentity(
          trustchainId,
          args.at(TrustchainPrivateKeyOpt).asString(),
          Tanker::SUserId{userId});
  }();

  writefile(identityFile, identity);
  return identity;
}

auto const sdkType = "test";
auto const sdkVersion = "0.0.1";

AsyncCorePtr signUp(MainArgs const& args)
{
  auto const trustchainId = args.at("<trustchainid>").asString();
  auto const userId = args.at("<userid>").asString();

  auto const identity = loadIdentity(trustchainId, userId, args);

  auto core = AsyncCorePtr{new AsyncCore(
      args.at("<trustchainurl>").asString(),
      {sdkType,
       cppcodec::base64_rfc4648::decode<Tanker::Trustchain::TrustchainId>(
           trustchainId),
       sdkVersion},
      ".")};

  auto const status = core->start(identity).get();
  if (status != Tanker::Status::Ready && !args.at(UnlockPasswordOpt))
    throw std::runtime_error("Please provide a password");
  core->registerIdentity(
          Tanker::Passphrase{args.at(UnlockPasswordOpt).asString()})
      .get();

  return core;
}

AsyncCorePtr signIn(MainArgs const& args)
{
  auto const trustchainId = args.at("<trustchainid>").asString();
  auto const userId = args.at("<userid>").asString();

  auto const identity = loadIdentity(trustchainId, userId, args);

  auto core = AsyncCorePtr{new AsyncCore(
      args.at("<trustchainurl>").asString(),
      {sdkType,
       cppcodec::base64_rfc4648::decode<Tanker::Trustchain::TrustchainId>(
           trustchainId),
       sdkVersion},
      ".")};

  Unlock::Verification verification;
  if (args.at(VerificationKeyOpt))
    verification = VerificationKey{args.at(VerificationKeyOpt).asString()};
  else if (args.at(UnlockPasswordOpt))
    verification = Passphrase{args.at(UnlockPasswordOpt).asString()};

  auto const status = core->start(identity).get();
  if (status != Tanker::Status::IdentityVerificationNeeded)
    throw std::runtime_error(
        "Failed to sign in: "
        "identity not registered");
  core->verifyIdentity(verification).get();

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
          cppcodec::base64_rfc4648::decode(args.at("<block>").asString()));

    auto const entry = blockToServerEntry(block);
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
      block.author = Crypto::Hash(
          cppcodec::hex_lower::decode(args.at("<author>").asString()));
      block.signature = Crypto::Signature(
          cppcodec::hex_lower::decode(args.at("<signature>").asString()));
    }
    else
    {
      block.payload =
          cppcodec::base64_rfc4648::decode(args.at("<payload>").asString());
      block.author = Crypto::Hash(
          cppcodec::base64_rfc4648::decode(args.at("<author>").asString()));
      block.signature = Crypto::Signature(
          cppcodec::base64_rfc4648::decode(args.at("<signature>").asString()));
    }

    auto const entry = blockToServerEntry(block);
    std::cout << formatEntry(block, entry) << std::endl;
  }
  else if (args.at("signup").asBool())
  {
    auto const core = signUp(args);
  }
  else if (args.at("signin").asBool())
  {
    auto const core = signIn(args);
  }
  else if (args.at("createidentity").asBool())
  {
    fmt::print("{}\n", createIdentity(args));
  }
  else if (args.at("encrypt").asBool())
  {
    auto const trustchainId =
        cppcodec::base64_rfc4648::decode<Tanker::Trustchain::TrustchainId>(
            args.at("<trustchainid>").asString());

    auto const core = signIn(args);

    std::vector<Tanker::SUserId> shareTo;
    if (args.at("--share"))
      shareTo.push_back(SUserId{args.at("--share").asString()});

    std::vector<Tanker::SPublicIdentity> shareToPublicIdentities;
    for (auto const& userId : shareTo)
      shareToPublicIdentities.push_back(
          SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
              trustchainId, obfuscateUserId(userId, trustchainId)})});

    auto const cleartext = args.at("<cleartext>").asString();
    std::vector<uint8_t> encrypted(AsyncCore::encryptedSize(cleartext.size()));

    core->encrypt(encrypted.data(),
                  gsl::make_span(cleartext).as_span<uint8_t const>(),
                  shareToPublicIdentities)
        .get();
    fmt::print("encrypted: {}\n", cppcodec::base64_rfc4648::encode(encrypted));
  }
  else if (args.at("decrypt").asBool())
  {
    auto const core = signIn(args);

    auto const encrypteddata =
        cppcodec::base64_rfc4648::decode(args.at("<encrypteddata>").asString());
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
