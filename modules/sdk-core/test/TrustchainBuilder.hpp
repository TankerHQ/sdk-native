#pragma once

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/SecretProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember2.hpp>
#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/User.hpp>

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace Tanker::Users
{
class ContactStore;
class UserKeyStore;
}

class TrustchainBuilder
{
public:
  struct Device
  {
    Tanker::DeviceKeys keys;
    Tanker::Trustchain::DeviceId id;
    Tanker::Trustchain::UserId userId;
    Tanker::Identity::Delegation delegation;
    uint64_t blockIndex;

    Tanker::Users::Device asTankerDevice() const;
  };

  struct UserKey
  {
    Tanker::Crypto::EncryptionKeyPair keyPair;
    uint64_t blockIndex;
  };

  struct User
  {
    Tanker::SUserId suserId;
    Tanker::Trustchain::UserId userId;
    std::vector<Device> devices;
    std::vector<UserKey> userKeys;
    uint64_t blockIndex;

    Tanker::Users::User asTankerUser() const;
  };

  struct ResultUser
  {
    User user;
    Tanker::Trustchain::ServerEntry entry;
  };

  struct ResultDevice
  {
    Device device;
    Tanker::Users::User user;
    Tanker::Trustchain::ServerEntry entry;
  };

  struct ProvisionalUser
  {
    Tanker::SecretProvisionalUser secretProvisionalUser;
    Tanker::PublicProvisionalUser publicProvisionalUser;
    Tanker::SPublicIdentity spublicIdentity;
  };

  struct InternalGroup
  {
    Tanker::InternalGroup tankerGroup;
    Tanker::Crypto::SealedPrivateSignatureKey encryptedPrivateSignatureKey;
    std::vector<Tanker::SUserId> members;
    std::vector<Tanker::Trustchain::Actions::UserGroupProvisionalMember2>
        provisionalMembers;

    Tanker::ExternalGroup asExternalGroup() const;
  };

  struct ResultGroup
  {
    InternalGroup group;
    Tanker::Trustchain::ServerEntry entry;
  };

  TrustchainBuilder();

  ResultUser makeUser(std::string const& suserId);
  ResultUser makeUser1(std::string const& suserId);
  ResultUser makeUser3(std::string const& suserId);
  ResultDevice makeDevice(std::string const& suserId,
                          int validatorDeviceIndex = 0);
  ResultDevice makeDevice1(std::string const& suserId,
                           int validatorDeviceIndex = 0);
  ResultDevice makeDevice3(std::string const& suserId,
                           int validatorDeviceIndex = 0);

  ResultGroup makeGroup(
      Device const& author,
      std::vector<User> const& users,
      std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers = {});
  ResultGroup makeGroup1(Device const& author, std::vector<User> const& users);
  ResultGroup makeGroup2(
      Device const& author,
      std::vector<User> const& users,
      std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers);
  ResultGroup addUserToGroup(Device const& author,
                             InternalGroup group,
                             std::vector<User> const& users);
  ResultGroup addUserToGroup2(
      Device const& author,
      InternalGroup group,
      std::vector<User> const& users,
      std::vector<Tanker::PublicProvisionalUser> const& provisionalUsers);

  ProvisionalUser makeProvisionalUser(std::string const& email);
  Tanker::PublicProvisionalUser toPublicProvisionalUser(
      Tanker::SecretProvisionalUser const& u) const;
  Tanker::Trustchain::ServerEntry claimProvisionalIdentity(
      std::string const& userId,
      Tanker::SecretProvisionalUser const& provisionalUser,
      int authorDeviceIndex = 0);

  std::vector<Tanker::Trustchain::Block> shareToDevice(
      Device const& sender,
      User const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Trustchain::Block shareToUser(
      Device const& sender,
      User const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Trustchain::Block shareToUserGroup(
      Device const& sender,
      InternalGroup const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Trustchain::Block shareToProvisionalUser(
      Device const& sender,
      Tanker::PublicProvisionalUser const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);

  Tanker::Trustchain::Block revokeDevice1(Device const& sender,
                                          Device const& target,
                                          bool unsafe = false);
  Tanker::Trustchain::Block revokeDevice2(Device const& sender,
                                          Device const& target,
                                          User const& user,
                                          bool unsafe = false);

  std::optional<User> findUser(std::string const& suserId) const;

  Tanker::BlockGenerator makeBlockGenerator(
      TrustchainBuilder::Device const& device) const;
  std::unique_ptr<Tanker::Users::UserKeyStore> makeUserKeyStore(
      User const& user, Tanker::DataStore::ADatabase* conn) const;
  std::unique_ptr<Tanker::Users::ContactStore> makeContactStoreWith(
      std::vector<std::string> const& suserIds,
      Tanker::DataStore::ADatabase* conn) const;
  std::vector<Tanker::Group> getGroupsOfUser(
      TrustchainBuilder::User const& user) const;
  std::unique_ptr<Tanker::Groups::Store> makeGroupStore(
      TrustchainBuilder::User const& user,
      Tanker::DataStore::ADatabase* conn) const;
  std::unique_ptr<Tanker::Groups::Store> makeGroupStore(
      std::vector<Tanker::Trustchain::GroupId> const& groups,
      Tanker::DataStore::ADatabase* conn) const;
  std::unique_ptr<Tanker::ProvisionalUserKeysStore>
  makeProvisionalUserKeysStoreWith(
      std::vector<ProvisionalUser> const& provisionalUsers,
      Tanker::DataStore::ADatabase* conn) const;

  std::vector<Tanker::Trustchain::ServerEntry> const& entries() const;
  std::vector<InternalGroup> groups() const;
  std::vector<User> const& users() const;

  Tanker::Trustchain::TrustchainId const& trustchainId() const;
  Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey() const;

private:
  struct GroupComparator
  {
    bool operator()(InternalGroup const& l, InternalGroup const& r) const
    {
      return l.tankerGroup.id < r.tankerGroup.id;
    }
  };

  Tanker::Crypto::SignatureKeyPair _trustchainKeyPair;
  Tanker::Trustchain::TrustchainId _trustchainId;

  std::vector<User> _users;
  std::set<InternalGroup, GroupComparator> _groups;
  std::vector<Tanker::Trustchain::ServerEntry> _entries;

  User* findMutableUser(Tanker::SUserId const& suserId);
};
