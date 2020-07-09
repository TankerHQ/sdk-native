#include <fstream>
#include <iostream>
#include <sstream>

#include <mgs/base16.hpp>
#include <mgs/base64.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/KeyPublishAction.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserAction.hpp>

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
using CliAction = boost::variant2::variant<Actions::TrustchainCreation,
                                           Actions::DeviceCreation1,
                                           Actions::DeviceCreation2,
                                           Actions::DeviceCreation3,
                                           Actions::DeviceRevocation1,
                                           Actions::DeviceRevocation2,
                                           Actions::UserGroupCreation1,
                                           Actions::UserGroupCreation2,
                                           Actions::UserGroupAddition1,
                                           Actions::UserGroupAddition2,
                                           Actions::KeyPublishToUser,
                                           Actions::KeyPublishToUserGroup,
                                           Actions::KeyPublishToProvisionalUser,
                                           Actions::ProvisionalIdentityClaim>;

CliAction deserializeAction(gsl::span<std::uint8_t const> block)
{
  if (block.size() < 2)
    throw std::runtime_error("block too small");
  if (block[0] != 1)
    throw std::runtime_error(
        fmt::format("unsupported block version: {}", block[0]));

  auto rest = Serialization::varint_read(block.subspan(1)).second;
  auto const nature = static_cast<Nature>(rest[32]);

  switch (nature)
  {
  case Nature::TrustchainCreation:
    return Serialization::deserialize<TrustchainCreation>(block);
  case Nature::DeviceCreation1:
    return Serialization::deserialize<DeviceCreation1>(block);
  case Nature::DeviceCreation2:
    return Serialization::deserialize<DeviceCreation2>(block);
  case Nature::DeviceCreation3:
    return Serialization::deserialize<DeviceCreation3>(block);
  case Nature::DeviceRevocation1:
    return Serialization::deserialize<DeviceRevocation1>(block);
  case Nature::DeviceRevocation2:
    return Serialization::deserialize<DeviceRevocation2>(block);
  case Nature::UserGroupCreation1:
    return Serialization::deserialize<UserGroupCreation1>(block);
  case Nature::UserGroupCreation2:
    return Serialization::deserialize<UserGroupCreation2>(block);
  case Nature::UserGroupAddition1:
    return Serialization::deserialize<UserGroupAddition1>(block);
  case Nature::UserGroupAddition2:
    return Serialization::deserialize<UserGroupAddition2>(block);
  case Nature::KeyPublishToDevice:
    throw std::runtime_error("key publish to device are not supported anymore");
  case Nature::KeyPublishToUser:
    return Serialization::deserialize<KeyPublishToUser>(block);
  case Nature::KeyPublishToUserGroup:
    return Serialization::deserialize<KeyPublishToUserGroup>(block);
  case Nature::KeyPublishToProvisionalUser:
    return Serialization::deserialize<KeyPublishToProvisionalUser>(block);
  case Nature::ProvisionalIdentityClaim:
    return Serialization::deserialize<ProvisionalIdentityClaim>(block);
  }
  throw std::runtime_error(
      fmt::format(TFMT("unknown nature: {}"), static_cast<int>(nature)));
}

std::string formatAction(CliAction const& action)
{
  return boost::variant2::visit(
      [](auto const& e) { return nlohmann::json(e).dump(4); }, action);
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
       mgs::base64::decode<Tanker::Trustchain::TrustchainId>(trustchainId),
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
       mgs::base64::decode<Tanker::Trustchain::TrustchainId>(trustchainId),
       sdkVersion},
      ".")};

  Unlock::Verification verification;
  if (args.at(VerificationKeyOpt))
    verification = VerificationKey{args.at(VerificationKeyOpt).asString()};
  else if (args.at(UnlockPasswordOpt))
    verification = Passphrase{args.at(UnlockPasswordOpt).asString()};

  auto const status = core->start(identity).get();
  if (status == Tanker::Status::Ready)
    return core;
  if (status != Tanker::Status::IdentityVerificationNeeded)
    throw std::runtime_error("Failed to sign in: identity not registered");
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
    CliAction action;

    if (args.at("--hex").asBool())
      action =
          deserializeAction(mgs::base16::decode(args.at("<block>").asString()));
    else
      action =
          deserializeAction(mgs::base64::decode(args.at("<block>").asString()));

    std::cout << formatAction(action) << std::endl;
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
        mgs::base64::decode<Tanker::Trustchain::TrustchainId>(
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
    fmt::print("encrypted: {}\n", mgs::base64::encode(encrypted));
  }
  else if (args.at("decrypt").asBool())
  {
    auto const core = signIn(args);

    auto const encrypteddata =
        mgs::base64::decode(args.at("<encrypteddata>").asString());
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
