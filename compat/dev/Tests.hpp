#pragma once

#include "Command.hpp"
#include "Helpers.hpp"
#include "States.hpp"

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>

#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/operations.hpp>
#include <cppcodec/base64_rfc4648.hpp>

using namespace std::string_literals;

using Tanker::Compat::Command;
using Tanker::Test::User;

struct EncryptCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);
    auto bob = signUpUser(trustchain, tankerPath);

    auto clearData = "my confession to bob"s;
    auto encryptedData =
        encrypt(alice.core,
                clearData,
                {Tanker::SPublicIdentity{
                    Tanker::Identity::getPublicIdentity(bob.user.identity)}},
                {});

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                nonstd::nullopt,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = signInUser(bob.identity, trustchain, tankerPath);
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore = signInUser(alice.identity, trustchain, tankerPath);
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
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bob = signUpUser(trustchain, tankerPath);
    bob.core->signOut().get();

    auto sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(bob.user.identity)}})
            .get();

    auto clearData = "my little speech"s;
    auto encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                sgroupId,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = signInUser(bob.identity, trustchain, tankerPath);
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore = signInUser(alice.identity, trustchain, tankerPath);
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
                     {{"alice", alice}, {"password", "my password"}});
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
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});

    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};

    auto const clearData = "my love letter to bob "s;
    auto const encryptedData =
        encrypt(alice.core, clearData, {bobPublicProvisionalIdentity}, {});

    Tanker::saveJson(
        statePath,
        {{"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto bob = signUpProvisionalUser(json.at("bob_provisional_identity"),
                                     "bob@tanker.io",
                                     trustchain,
                                     tankerPath);
    auto const encryptState = json.at("encrypt_state").get<EncryptState>();
    decrypt(bob.core, encryptState.encryptedData, encryptState.clearData);
  }
};

struct DecryptOldClaim : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};
    auto const clearData = "my love letter to bob"s;
    auto const encryptedData =
        encrypt(alice.core, clearData, {bobPublicProvisionalIdentity}, {});

    auto bob = signUpProvisionalUser(
        Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
        "bob@tanker.io",
        trustchain,
        tankerPath);

    Tanker::saveJson(
        statePath,
        {
            {"bob_identity", bob.user.identity},
            {"encrypt_state", EncryptState{clearData, encryptedData}},
        });
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bobIdentity = json.at("bob_identity").get<std::string>();
    auto const state = json.at("encrypt_state").get<EncryptState>();
    auto bobCore = signInUser(bobIdentity, trustchain, tankerPath);
    decrypt(bobCore, state.encryptedData, state.clearData);
  }
};

struct ProvisionalUserGroupClaim : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();
    auto const clearData = "My allocution to the world";
    auto const encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    Tanker::saveJson(
        statePath,
        {{"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto bob = signUpProvisionalUser(json.at("bob_provisional_identity"),
                                     "bob@tanker.io",
                                     trustchain,
                                     tankerPath);
    auto const encryptState = json.at("encrypt_state").get<EncryptState>();
    decrypt(bob.core, encryptState.encryptedData, encryptState.clearData);
  }
};

struct ProvisionalUserGroupOldClaim : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();
    auto const clearData = "My old allocution to the world";
    auto const encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    auto bob = signUpProvisionalUser(
        Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
        "bob@tanker.io",
        trustchain,
        tankerPath);

    Tanker::saveJson(
        statePath,
        {{"bob_identity", bob.user.identity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bobIdentity = json.at("bob_identity").get<std::string>();
    auto const state = json.at("encrypt_state").get<EncryptState>();
    auto bobCore = signInUser(bobIdentity, trustchain, tankerPath);
    decrypt(bobCore, state.encryptedData, state.clearData);
  }
};

struct ClaimProvisionalSelf : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});

    auto const sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();

    auto bob = signUpUser(trustchain, tankerPath);

    auto const clearData = "My statement to the world";
    auto const encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    encrypt(bob.core, "", {}, {sgroupId});
    Tanker::saveJson(
        statePath,
        {{"bob_identity", bob.user.identity},
         {"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const bobIdentity = json.at("bob_identity").get<std::string>();
    auto bobCore = signInUser(bobIdentity, trustchain, tankerPath);
    claim(bobCore,
          trustchain,
          json.at("bob_provisional_identity")
              .get<Tanker::SSecretProvisionalIdentity>(),
          "bob@tanker.io");
    auto const state = json.at("encrypt_state").get<EncryptState>();
    decrypt(bobCore, state.encryptedData, state.clearData);
  }
};
