#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/Actions/UserGroupProvisionalMember2.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/User.hpp>

#include <optional>
#include <set>
#include <string>
#include <vector>

class TrustchainBuilder
{
public:
  struct Device
  {
    Tanker::DeviceKeys keys;
    Tanker::Trustchain::DeviceId id;
    Tanker::Trustchain::UserId userId;
    Tanker::Identity::Delegation delegation;
    bool isRevoked = false;

    Tanker::Users::Device asTankerDevice() const;
  };

  struct UserKey
  {
    Tanker::Crypto::EncryptionKeyPair keyPair;
    uint64_t blockIndex;
    inline operator Tanker::Crypto::EncryptionKeyPair const&() const
    {
      return keyPair;
    }
  };

  struct User
  {
    Tanker::SUserId suserId;
    Tanker::Trustchain::UserId userId;
    std::vector<Device> devices;
    std::vector<UserKey> userKeys;
    uint64_t blockIndex;
    std::vector<Tanker::Trustchain::ServerEntry> entries;

    Tanker::Users::User asTankerUser() const;
    std::optional<Device> findDevice(
        Tanker::Trustchain::DeviceId const& id) const;
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
    Tanker::ProvisionalUsers::SecretUser secretProvisionalUser;
    Tanker::ProvisionalUsers::PublicUser publicProvisionalUser;
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

  ResultGroup makeGroup(Device const& author,
                        std::vector<User> const& users,
                        std::vector<Tanker::ProvisionalUsers::PublicUser> const&
                            provisionalUsers = {});
  ResultGroup makeGroup1(Device const& author, std::vector<User> const& users);
  ResultGroup makeGroup2(
      Device const& author,
      std::vector<User> const& users,
      std::vector<Tanker::ProvisionalUsers::PublicUser> const&
          provisionalUsers);
  ResultGroup addUserToGroup(Device const& author,
                             InternalGroup group,
                             std::vector<User> const& users);
  ResultGroup addUserToGroup2(
      Device const& author,
      InternalGroup group,
      std::vector<User> const& users,
      std::vector<Tanker::ProvisionalUsers::PublicUser> const&
          provisionalUsers);

  ProvisionalUser makeProvisionalUser(std::string const& email);
  Tanker::ProvisionalUsers::PublicUser toPublicProvisionalUser(
      Tanker::ProvisionalUsers::SecretUser const& u) const;
  Tanker::Trustchain::ServerEntry claimProvisionalIdentity(
      std::string const& userId,
      Tanker::ProvisionalUsers::SecretUser const& provisionalUser,
      int authorDeviceIndex = 0);

  Tanker::Trustchain::ServerEntry shareToUser(
      Device const& sender,
      User const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Trustchain::ServerEntry shareToUserGroup(
      Device const& sender,
      InternalGroup const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Trustchain::ServerEntry shareToProvisionalUser(
      Device const& sender,
      Tanker::ProvisionalUsers::PublicUser const& receiver,
      Tanker::Trustchain::ResourceId const& resourceId,
      Tanker::Crypto::SymmetricKey const& key);

  Tanker::Trustchain::ServerEntry revokeDevice1(Device const& sender,
                                                Device const& target,
                                                bool unsafe = false);
  Tanker::Trustchain::ServerEntry revokeDevice2(Device const& sender,
                                                Device const& target,
                                                bool unsafe = false);

  std::optional<User> findUser(std::string const& suserId) const;

  std::unique_ptr<Tanker::Users::LocalUserStore> makeLocalUserStore(
      User const& user, Tanker::DataStore::ADatabase* conn) const;
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

  Tanker::Trustchain::Context const& trustchainContext() const;
  Tanker::Trustchain::TrustchainId const& trustchainId() const;
  Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey() const;
  Tanker::Crypto::PublicSignatureKey const& trustchainPublicKey() const;

private:
  struct GroupComparator
  {
    bool operator()(InternalGroup const& l, InternalGroup const& r) const
    {
      return l.tankerGroup.id < r.tankerGroup.id;
    }
  };

  Tanker::Trustchain::Context _context;
  Tanker::Crypto::PrivateSignatureKey _trustchainPrivateSignatureKey;

  std::vector<User> _users;
  std::set<InternalGroup, GroupComparator> _groups;
  std::vector<Tanker::Trustchain::ServerEntry> _entries;

  User* findMutableUser(Tanker::SUserId const& suserId);
  User* findMutableUserByDeviceId(Tanker::Trustchain::DeviceId const& deviceId);
};
