#pragma once
#include <Tanker/Compat/Command.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Version.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/JsonFile.hpp>

#include <nlohmann/json.hpp>
#include <optional.hpp>

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

struct EncryptState
{
  std::string clearData;
  std::vector<uint8_t> encryptedData;
};

void to_json(nlohmann::json& j, EncryptState const& state)
{
  j["clear_data"] = state.clearData;
  j["encrypted_data"] = cppcodec::base64_rfc4648::encode(state.encryptedData);
}

void from_json(nlohmann::json const& j, EncryptState& state)
{
  j.at("clear_data").get_to(state.clearData);
  auto const str = j.at("encrypted_data").get<std::string>();
  state.encryptedData =
      cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(str);
}

struct ShareState
{
  User alice;
  User bob;
  nonstd::optional<Tanker::SGroupId> groupId;
  EncryptState encryptState;
};

void to_json(nlohmann::json& j, ShareState const& state)
{
  j["alice"] = state.alice;
  j["bob"] = state.bob;
  if (state.groupId)
    j["group"] = state.groupId.value();
  j["encrypt_state"] = state.encryptState;
}

void from_json(nlohmann::json const& j, ShareState& state)
{
  j.at("alice").get_to(state.alice);
  j.at("bob").get_to(state.bob);
  auto group = j.find("group");
  if (group != j.end())
    state.groupId = group->get<Tanker::SGroupId>();
  state.encryptState = j.at("encrypt_state").get<EncryptState>();
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
  {
    throw std::runtime_error("failed to decrypt");
  }
}

std::vector<uint8_t> encrypt(CorePtr& core,
                             std::string clearData,
                             std::vector<Tanker::SUserId> users,
                             std::vector<Tanker::SGroupId> groups)
{
  auto const buffer = Tanker::make_buffer(clearData);
  auto encryptedData =
      std::vector<uint8_t>(Tanker::AsyncCore::encryptedSize(clearData.size()));

  core->encrypt(encryptedData.data(), buffer, users, groups).get();
  return encryptedData;
}
}

struct EncryptCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain->createUser();

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->open(alice.suserId, alice.user_token).get();

    auto const bob = trustchain->createUser();
    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->open(bob.suserId, bob.user_token).get();
    bobCore->close().get();

    auto clearData = "my confession to bob"s;

    auto encryptedData = encrypt(aliceCore, clearData, {bob.suserId}, {});

    Tanker::saveJson(statePath,
                     ShareState{alice,
                                bob,
                                nonstd::nullopt,
                                EncryptState{clearData, encryptedData}});
    aliceCore->close().get();
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->open(state.bob.suserId, state.bob.user_token).get();
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
    bobCore->close().get();

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->open(state.alice.suserId, state.alice.user_token).get();
    decrypt(aliceCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
    aliceCore->close().get();
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
    aliceCore->open(alice.suserId, alice.user_token).get();

    auto const bob = trustchain->createUser();
    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->open(bob.suserId, bob.user_token).get();
    bobCore->close().get();

    auto sgroupId = aliceCore->createGroup({alice.suserId, bob.suserId}).get();

    auto clearData = "my little speech"s;
    auto encryptedData = encrypt(aliceCore, clearData, {}, {sgroupId});

    Tanker::saveJson(
        statePath,
        ShareState{
            alice, bob, sgroupId, EncryptState{clearData, encryptedData}});
    aliceCore->close().get();
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto bobCore = createCore(trustchain->url(), trustchain->id(), tankerPath);
    bobCore->open(state.bob.suserId, state.bob.user_token).get();
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->open(state.alice.suserId, state.alice.user_token).get();
    decrypt(aliceCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

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
    aliceCore->open(alice.suserId, alice.user_token).get();
    aliceCore
        ->registerUnlock(Tanker::Unlock::RegistrationOptions{}.set(
            Tanker::Password{"my password"}))
        .get();
    aliceCore->close().get();
    Tanker::saveJson(statePath,
                     {{"alice", alice}, {"password", "my password"}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const alice = json.at("alice").get<User>();
    auto const password = json.at("password").get<Tanker::Password>();

    auto aliceCore =
        createCore(trustchain->url(), trustchain->id(), tankerPath);
    aliceCore->unlockRequired().connect(
        [&] { aliceCore->unlockCurrentDevice(password); });
    aliceCore->open(alice.suserId, alice.user_token).get();
    fmt::print("is open!\n");
  }
};
