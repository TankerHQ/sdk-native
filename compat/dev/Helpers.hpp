#pragma once

#include <Tanker/AsyncCore.hpp>

#include <Tanker/Test/Functional/Trustchain.hpp>
#include <Tanker/Test/Functional/User.hpp>

struct AsyncCoreDeleter
{
  void operator()(Tanker::AsyncCore* core) const
  {
    core->destroy().get();
  }
};

using CorePtr = std::unique_ptr<Tanker::AsyncCore, AsyncCoreDeleter>;

CorePtr createCore(std::string const& url,
                   Tanker::Trustchain::TrustchainId const& id,
                   std::string const& tankerPath);

struct UserSession
{
  CorePtr core;
  Tanker::Test::User user;
};

UserSession signUpUser(Tanker::Test::Trustchain& trustchain,
                       std::string const& tankerPath);

void claim(CorePtr& core,
           Tanker::Test::Trustchain& trustchain,
           Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
           std::string const& email);

UserSession signUpProvisionalUser(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    Tanker::Test::Trustchain& trustchain,
    std::string const& tankerPath);

CorePtr signInUser(std::string const& identity,
                   Tanker::Test::Trustchain& trustchain,
                   std::string const& tankerPath);

void decrypt(CorePtr const& core,
             std::vector<uint8_t> const& encryptedData,
             std::string const& expectedData);

std::vector<uint8_t> encrypt(CorePtr& core,
                             std::string clearData,
                             std::vector<Tanker::SPublicIdentity> users,
                             std::vector<Tanker::SGroupId> groups);

Tanker::Test::User upgradeToIdentity(
    Tanker::Trustchain::TrustchainId const& trustchainId,
    Tanker::Test::User user);
