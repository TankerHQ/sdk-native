#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <utility>

namespace Tanker
{
namespace Users
{
class ContactStore;
class LocalUser;
struct User;
}

struct ExternalGroup;

namespace DataStore
{
class ADatabase;
}

class TrustchainVerifier
{
public:
  TrustchainVerifier(Trustchain::TrustchainId const&,
                     Users::LocalUser*,
                     Users::ContactStore*);

  TrustchainVerifier(TrustchainVerifier const&) = delete;
  TrustchainVerifier(TrustchainVerifier&&) = delete;
  TrustchainVerifier& operator=(TrustchainVerifier const&) = delete;
  TrustchainVerifier& operator=(TrustchainVerifier&&) = delete;

  tc::cotask<Entry> verify(Trustchain::ServerEntry const&) const;

private:
  tc::cotask<Entry> handleDeviceCreation(
      Trustchain::ServerEntry const& dc) const;
  tc::cotask<Entry> handleDeviceRevocation(
      Trustchain::ServerEntry const& dr) const;

  tc::cotask<Users::User> getUser(Trustchain::UserId const& userId) const;
  tc::cotask<std::pair<Users::User, std::size_t>> getUserByDeviceId(
      Trustchain::DeviceId const& deviceId) const;
  Users::Device getDevice(Users::User const& user,
                          Trustchain::DeviceId const& deviceHash) const;

  Trustchain::TrustchainId _trustchainId;
  Users::LocalUser* _localUser;
  Users::ContactStore* _contacts;
};
}
