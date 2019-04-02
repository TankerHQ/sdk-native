#pragma once
#include <Tanker/Compat/Command.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Version.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/operations.hpp>

using namespace std::string_literals;
using CorePtr = std::unique_ptr<Tanker::AsyncCore>;

using Tanker::Compat::Command;
using Tanker::Compat::Trustchain;
using Tanker::Compat::TrustchainFactory;
using Tanker::Compat::User;
namespace
{
CorePtr createCore(std::string const& url,
                   Tanker::TrustchainId const& id,
                   std::string const& tankerPath)
{
  return std::make_unique<Tanker::AsyncCore>(
      url, Tanker::SdkInfo{"test", id, TANKER_VERSION}, tankerPath);
}
}

struct EncryptState
{
  User alice;
  User bob;
  nonstd::optional<Tanker::SGroupId> groupId;
  std::string clearData;
  std::vector<uint8_t> encryptedData;
};

void to_json(nlohmann::json& j, EncryptState const& state)
{
  j["alice"] = state.alice;
  j["bob"] = state.bob;
  if (state.groupId)
    j["group"] = state.groupId.value();
  j["clear_data"] = state.clearData;
  j["encrypted_data"] = Tanker::base64::encode(state.encryptedData);
}

void from_json(nlohmann::json const& j, EncryptState& state)
{
  j.at("alice").get_to(state.alice);
  j.at("bob").get_to(state.bob);
  auto group = j.find("group");
  if (group != j.end())
    state.groupId = group->get<Tanker::SGroupId>();
  j.at("clear_data").get_to(state.clearData);
  auto const str = j.at("encrypted_data").get<std::string>();
  state.encryptedData = Tanker::base64::decode<std::vector<uint8_t>>(str);
}

void decrypt(CorePtr const& core,
             std::vector<uint8_t> encryptedData,
             std::string expectedData)
{
  auto decryptedData = std::vector<uint8_t>(
      Tanker::AsyncCore::decryptedSize(encryptedData).get());
  core->decrypt(decryptedData.data(), encryptedData).get();
  fmt::print(">> {}\n",
             std::string(decryptedData.begin(), decryptedData.end()));
  if (std::string(decryptedData.begin(), decryptedData.end()) != expectedData)
    throw std::runtime_error("failed to decrypt");
}

std::vector<uint8_t> encrypt(CorePtr& core,
                             std::string clearData,
                             std::vector<Tanker::SPublicIdentity> users,
                             std::vector<Tanker::SGroupId> groups)
{
  auto const buffer = Tanker::make_buffer(clearData);
  auto encryptedData =
      std::vector<uint8_t>(Tanker::AsyncCore::encryptedSize(clearData.size()));

  core->encrypt(encryptedData.data(), buffer, users, groups).get();
  return encryptedData;
}

User upgradeToIdentity(Tanker::TrustchainId const& trustchainId, User user)
{
  if (user.user_token)
  {
    user.identity =
        Tanker::Identity::upgradeUserToken(Tanker::base64::encode(trustchainId),
                                           user.suserId,
                                           user.user_token.value());
    user.user_token.reset();
  }
  return user;
}

struct EncryptCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain->createUser();

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->signUp(alice.identity).get();

    auto const bob = trustchain->createUser();
    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->signUp(bob.identity).get();
    bobCore->signOut().get();

    auto clearData = "my confession to bob"s;

    auto encryptedData =
        encrypt(aliceCore,
                clearData,
                {Tanker::SPublicIdentity{
                    Tanker::Identity::getPublicIdentity(bob.identity)}},
                {});

    Tanker::saveJson(
        statePath,
        EncryptState{alice, bob, nonstd::nullopt, clearData, encryptedData});
    aliceCore->signOut().get();
  }

  void next() override
  {
    EncryptState state = Tanker::loadJson(statePath);

    auto alice = upgradeToIdentity(trustchain->id(), state.alice);
    auto bob = upgradeToIdentity(trustchain->id(), state.bob);

    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->signIn(bob.identity).get();
    decrypt(bobCore, state.encryptedData, state.clearData);
    bobCore->signOut().get();

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->signIn(alice.identity).get();
    decrypt(aliceCore, state.encryptedData, state.clearData);
    aliceCore->signOut().get();
  }
};

struct GroupCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain->createUser();
    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->signUp(alice.identity).get();

    auto const bob = trustchain->createUser();
    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->signUp(bob.identity).get();
    bobCore->signOut().get();

    auto sgroupId =
        aliceCore
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.identity)},
                 Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(bob.identity)}})
            .get();

    auto clearData = "my little speech"s;
    auto encryptedData = encrypt(aliceCore, clearData, {}, {sgroupId});

    Tanker::saveJson(
        statePath,
        EncryptState{alice, bob, sgroupId, clearData, encryptedData});
    aliceCore->signOut().get();
  }

  void next() override
  {
    EncryptState state = Tanker::loadJson(statePath);

    auto alice = upgradeToIdentity(trustchain->id(), state.alice);
    auto bob = upgradeToIdentity(trustchain->id(), state.bob);

    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->signIn(bob.identity).get();
    decrypt(bobCore, state.encryptedData, state.clearData);

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->signIn(alice.identity).get();
    decrypt(aliceCore, state.encryptedData, state.clearData);

    auto clearData = "my updated speech"s;
    auto encryptedData =
        encrypt(aliceCore, clearData, {}, {state.groupId.value()});
    decrypt(bobCore, encryptedData, clearData);
  }
};

struct UnlockCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain->createUser();
    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    Tanker::AuthenticationMethods methods{Tanker::Password{"my password"}};
    aliceCore->signUp(alice.identity, methods).get();
    aliceCore->signOut().get();
    Tanker::saveJson(statePath,
                     {{"trustchainId", trustchain->id()},
                      {"alice", alice},
                      {"password", "my password"}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const alice =
        upgradeToIdentity(trustchain->id(), json.at("alice").get<User>());
    auto const password = json.at("password").get<Tanker::Password>();

    auto subDirForDevice = boost::filesystem::path(tankerPath) / "newDevice"s;
    boost::filesystem::create_directory(subDirForDevice);
    auto aliceCore = createCore(
        trustchain->url(), trustchain->id(), subDirForDevice.string());
    aliceCore->signIn(alice.identity, Tanker::SignInOptions{{}, {}, password})
        .get();
    fmt::print("is open!\n");
  }
};
