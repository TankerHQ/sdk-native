#pragma once

#include <Tanker/AsyncCore.hpp>

#include <Tanker/Functional/Trustchain.hpp>

#include <Compat/User.hpp>

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
  User user;
};

UserSession signUpUser(Tanker::Functional::Trustchain& trustchain,
                       std::string const& tankerPath);

void claim(CorePtr& core,
           Tanker::Functional::Trustchain& trustchain,
           Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
           std::string const& email,
           std::string const& verifCode);

UserSession signUpAndClaim(
    Tanker::SSecretProvisionalIdentity const& provisionalIdentity,
    std::string const& email,
    std::string const& verifCode,
    Tanker::Functional::Trustchain& trustchain,
    std::string const& tankerPath);

CorePtr signInUser(std::string const& identity,
                   Tanker::Functional::Trustchain& trustchain,
                   std::string const& tankerPath);

void decryptAndCheck(CorePtr const& core,
                     std::vector<uint8_t> const& encryptedData,
                     std::string const& expectedData);

User upgradeToIdentity(
    Tanker::Trustchain::TrustchainId const& trustchainId,
    User user);
