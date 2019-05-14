#pragma once

#include "Command.hpp"
#include "States.hpp"

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

tc::future<Tanker::VerificationCode> getVerificationCode(
    TrustchainId const& id, Tanker::Email const& email)
{
  return tc::async_resumable([=]() -> tc::cotask<Tanker::VerificationCode> {
    auto tf = TC_AWAIT(TrustchainFactory::create());
    TC_RETURN(TC_AWAIT(tf->getVerificationCode(id, email)));
  });
}

CorePtr createCore(std::string const& url,
                   Tanker::Trustchain::TrustchainId const& id,
                   std::string const& tankerPath)
{
  return std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>(
      new Tanker::AsyncCore(
          url, Tanker::SdkInfo{"test", id, TANKER_VERSION}, tankerPath),
      AsyncCoreDeleter{});
}

std::pair<CorePtr, std::string> signUpProvisionalUser(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    Tanker::Test::Trustchain& trustchain,
    std::string const& tankerPath)
{
  auto user = trustchain.makeUser();
  auto core = createCore(trustchain.url, trustchain.id, tankerPath);
  core->signUp(user.identity).get();
  auto const verifCode =
      getVerificationCode(trustchain.id, Tanker::Email{"bob@tanker.io"}).get();
  core->claimProvisionalIdentity(
          Tanker::SSecretProvisionalIdentity{provisionalIdentity}, verifCode)
      .get();
  return std::make_pair(std::move(core), user.identity);
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

    auto res = signUpProvisionalUser(
        Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
        "bob@tanker.io",
        trustchain,
        tankerPath);
    std::get<CorePtr>(res)->signOut().get();

    Tanker::saveJson(
        statePath,
        {
            {"bob_identity", std::get<std::string>(res)},
            {"encrypt_state", EncryptState{clearData, encryptedData}},
        });
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bobIdentity = json.at("bob_identity").get<std::string>();
    auto const state = json.at("encrypt_state").get<EncryptState>();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signIn(bobIdentity).get();
    decrypt(bobCore, state.encryptedData, state.clearData);
    bobCore->signOut().get();
  }
};

struct ProvisionalUserGroupClaim : Command
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
    auto const sgroupId =
        aliceCore
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();
    auto const clearData = "My allocution to the world";
    auto const encryptedData = encrypt(aliceCore, clearData, {}, {sgroupId});

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

struct ProvisionalUserGroupOldClaim : Command
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
    auto const sgroupId =
        aliceCore
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();
    auto const clearData = "My old allocution to the world";
    auto const encryptedData = encrypt(aliceCore, clearData, {}, {sgroupId});

    auto res = signUpProvisionalUser(
        Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
        "bob@tanker.io",
        trustchain,
        tankerPath);

    std::get<CorePtr>(res)->signOut().get();

    Tanker::saveJson(
        statePath,
        {{"bob_identity", std::get<std::string>(res)},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bobIdentity = json.at("bob_identity").get<std::string>();
    auto bobCore = createCore(trustchain.url, trustchain.id, tankerPath);
    bobCore->signIn(bobIdentity).get();
    auto const state = json.at("encrypt_state").get<EncryptState>();
    decrypt(bobCore, state.encryptedData, state.clearData);
    bobCore->signOut().get();
  }
};
