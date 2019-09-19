#pragma once

#include <Tanker/AsyncCore.hpp>

#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/User.hpp>

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
  Tanker::Functional::User user;
};

UserSession signUpUser(Tanker::Functional::Trustchain& trustchain,
                       std::string const& tankerPath);

void claim(CorePtr& core,
           Tanker::Functional::Trustchain& trustchain,
           Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
           std::string const& email);

UserSession signUpAndClaim(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    Tanker::Functional::Trustchain& trustchain,
    std::string const& tankerPath);

CorePtr signInUser(std::string const& identity,
                   Tanker::Functional::Trustchain& trustchain,
                   std::string const& tankerPath);

void decrypt(CorePtr const& core,
             std::vector<uint8_t> const& encryptedData,
             std::string const& expectedData);

std::vector<uint8_t> encrypt(CorePtr& core,
                             std::string clearData,
                             std::vector<Tanker::SPublicIdentity> users,
                             std::vector<Tanker::SGroupId> groups);

Tanker::Functional::User upgradeToIdentity(
    Tanker::Trustchain::TrustchainId const& trustchainId,
    Tanker::Functional::User user);
