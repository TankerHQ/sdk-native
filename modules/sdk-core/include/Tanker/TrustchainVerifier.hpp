#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <utility>

namespace Tanker
{
class ContactStore;
class GroupStore;
struct ExternalGroup;
struct User;
struct Device;

namespace DataStore
{
class ADatabase;
}

class TrustchainVerifier
{
public:
  TrustchainVerifier(Trustchain::TrustchainId const&,
                     DataStore::ADatabase*,
                     ContactStore*,
                     GroupStore*);

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
  tc::cotask<Entry> handleUserGroupAddition(
      Trustchain::ServerEntry const& ga) const;
  tc::cotask<Entry> handleUserGroupCreation(
      Trustchain::ServerEntry const& gc) const;
  tc::cotask<Entry> handleProvisionalIdentityClaim(
      Trustchain::ServerEntry const& claim) const;

  tc::cotask<User> getUser(Trustchain::UserId const& userId) const;
  tc::cotask<std::pair<User, std::size_t>> getUserByDeviceId(
      Trustchain::DeviceId const& deviceId) const;
  Device getDevice(User const& user,
                   Trustchain::DeviceId const& deviceHash) const;
  tc::cotask<ExternalGroup> getGroupByEncryptionKey(
      Crypto::PublicEncryptionKey const& recipientPublicEncryprionKey) const;
  tc::cotask<ExternalGroup> getGroupById(
      Trustchain::GroupId const& groupId) const;

  Trustchain::TrustchainId _trustchainId;
  DataStore::ADatabase* _db;
  ContactStore* _contacts;
  GroupStore* _groups;
};
}
