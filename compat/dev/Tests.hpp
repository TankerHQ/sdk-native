#pragma once

#include "Command.hpp"

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Version.hpp>

#include <Tanker/Test/Functional/TrustchainFactory.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/operations.hpp>
#include <cppcodec/base64_rfc4648.hpp>

using namespace std::string_literals;

using Tanker::Compat::Command;
using Tanker::Test::Trustchain;
using Tanker::Test::TrustchainFactory;
using Tanker::Test::User;
using Tanker::Trustchain::TrustchainId;

struct AsyncCoreDeleter
{
  void operator()(Tanker::AsyncCore* core) const
  {
    core->destroy().get();
  }
};

using CorePtr = std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>;

namespace
{
CorePtr createCore(std::string const& url,
                   Tanker::Trustchain::TrustchainId const& id,
                   std::string const& tankerPath)
{
  return std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>(
      new Tanker::AsyncCore(
          url, Tanker::SdkInfo{"test", id, TANKER_VERSION}, tankerPath),
      AsyncCoreDeleter{});
}

tc::future<Tanker::VerificationCode> getVerificationCode(
    TrustchainId const& id, Tanker::Email const& email)
{
  return tc::async_resumable([=]() -> tc::cotask<Tanker::VerificationCode> {
    auto tf = TC_AWAIT(TrustchainFactory::create());
    TC_RETURN(TC_AWAIT(tf->getVerificationCode(id, email)));
  });
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
             std::vector<uint8_t> const& encryptedData,
             std::string const& expectedData)
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

User upgradeToIdentity(Tanker::Trustchain::TrustchainId const& trustchainId,
                       User user)
{
  if (user.userToken)
  {
    user.identity = Tanker::Identity::upgradeUserToken(
        cppcodec::base64_rfc4648::encode(trustchainId),
        user.suserId,
        user.userToken.value());
    user.userToken.reset();
  }
  return user;
}
}

struct EncryptCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();

    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signUp(alice.identity).get();

    auto const bob = trustchain.makeUser();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signUp(bob.identity).get();
    bobCore->signOut().get();

    auto clearData = "my confession to bob"s;

    auto encryptedData =
        encrypt(aliceCore,
                clearData,
                {Tanker::SPublicIdentity{
                    Tanker::Identity::getPublicIdentity(bob.identity)}},
                {});

    Tanker::saveJson(statePath,
                     ShareState{alice,
                                bob,
                                nonstd::nullopt,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    ShareState state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signIn(bob.identity).get();
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signIn(alice.identity).get();
    decrypt(aliceCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
  }
};

struct GroupCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signUp(alice.identity).get();

    auto const bob = trustchain.makeUser();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
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
        ShareState{
            alice, bob, sgroupId, EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signIn(bob.identity).get();
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signIn(alice.identity).get();
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
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    Tanker::AuthenticationMethods methods{Tanker::Password{"my password"}};
    aliceCore->signUp(alice.identity, methods).get();
    Tanker::saveJson(statePath,
                     {{"trustchainId", trustchain.id},
                      {"alice", alice},
                      {"password", "my password"}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const alice =
        upgradeToIdentity(trustchain.id, json.at("alice").get<User>());
    auto const password = json.at("password").get<Tanker::Password>();

    auto subDirForDevice = boost::filesystem::path(tankerPath) / "newDevice"s;
    boost::filesystem::create_directory(subDirForDevice);
    auto aliceCore =
        createCore(trustchain.url, trustchain.id, subDirForDevice.string());
    aliceCore->signIn(alice.identity, Tanker::SignInOptions{{}, {}, password})
        .get();
    fmt::print("is open!\n");
  }
};

struct PreshareAndClaim : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signUp(alice.identity).get();
    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const clearData = "my love letter to bob "s;
    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};
    auto const encryptedData =
        encrypt(aliceCore, clearData, {bobPublicProvisionalIdentity}, {});
    Tanker::saveJson(
        statePath,
        {{"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bob = trustchain.makeUser();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signUp(bob.identity).get();
    auto const verifCode =
        getVerificationCode(trustchain.id, Tanker::Email{"bob@tanker.io"})
            .get();
    bobCore
        ->claimProvisionalIdentity(json.at("bob_provisional_identity"),
                                   verifCode)
        .get();
    auto const encryptState = json.at("encrypt_state").get<EncryptState>();
    decrypt(bobCore, encryptState.encryptedData, encryptState.clearData);
  }
};

struct DecryptOldClaim : Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->signUp(alice.identity).get();

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};
    auto const clearData = "my love letter to bob"s;
    auto const encryptedData =
        encrypt(aliceCore, clearData, {bobPublicProvisionalIdentity}, {});

    auto const bob = trustchain.makeUser();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signUp(bob.identity).get();
    auto const verifCode =
        getVerificationCode(trustchain.id, Tanker::Email{"bob@tanker.io"})
            .get();
    bobCore
        ->claimProvisionalIdentity(
            Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
            verifCode)
        .get();
    bobCore->signOut().get();

    Tanker::saveJson(
        statePath,
        {
            {"bob", bob},
            {"encrypt_state", EncryptState{clearData, encryptedData}},
        });
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bob = json.at("bob").get<User>();
    auto const state = json.at("encrypt_state").get<EncryptState>();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signIn(bob.identity).get();
    decrypt(bobCore, state.encryptedData, state.clearData);
    bobCore->signOut().get();
  }
};
