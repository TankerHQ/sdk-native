#pragma once

#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Device.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/User.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <optional.hpp>

#include <set>
#include <string>
#include <vector>

class TrustchainBuilder
{
public:
  struct Device
  {
    Tanker::DeviceKeys keys;
    Tanker::Identity::Delegation delegation;
    uint64_t blockIndex;

    Tanker::Device asTankerDevice() const;
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

    Tanker::User asTankerUser() const;
  };

  struct ResultUser
  {
    User user;
    Tanker::UnverifiedEntry entry;
  };

  struct ResultDevice
  {
    Device device;
    Tanker::User user;
    Tanker::UnverifiedEntry entry;
  };

  struct Group
  {
    Tanker::Group tankerGroup;
    Tanker::Crypto::SealedPrivateSignatureKey encryptedPrivateSignatureKey;
    std::vector<Tanker::SUserId> members;

    Tanker::ExternalGroup asExternalGroup() const;
  };

  struct ResultGroup
  {
    Group group;
    Tanker::UnverifiedEntry entry;
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

  ResultGroup makeGroup(Device const& author, std::vector<User> const& users);
  ResultGroup addUserToGroup(Device const& author,
                             Group group,
                             std::vector<User> const& users);

  std::vector<Tanker::Block> shareToDevice(
      Device const& sender,
      User const& receiver,
      Tanker::Crypto::Mac const& mac,
      Tanker::Crypto::SymmetricKey const& key);
  Tanker::Block shareToUser(Device const& sender,
                            User const& receiver,
                            Tanker::Crypto::Mac const& mac,
                            Tanker::Crypto::SymmetricKey const& key);
  Tanker::Block shareToUserGroup(Device const& sender,
                                 Group const& receiver,
                                 Tanker::Crypto::Mac const& resourceId,
                                 Tanker::Crypto::SymmetricKey const& key);

  Tanker::Block revokeDevice1(Device const& sender,
                              Device const& target,
                              bool unsafe = false);
  Tanker::Block revokeDevice2(Device const& sender,
                              Device const& target,
                              User const& user,
                              bool unsafe = false);

  nonstd::optional<User> getUser(std::string const& suserId) const;

  Tanker::BlockGenerator makeBlockGenerator(
      TrustchainBuilder::Device const& device) const;
  std::unique_ptr<Tanker::UserKeyStore> makeUserKeyStore(
      User const& user, Tanker::DataStore::ADatabase* conn) const;
  std::unique_ptr<Tanker::ContactStore> makeContactStoreWith(
      std::vector<std::string> const& suserIds,
      Tanker::DataStore::ADatabase* conn) const;
  std::unique_ptr<Tanker::GroupStore> makeGroupStore(
      TrustchainBuilder::User const& user,
      Tanker::DataStore::ADatabase* conn) const;

  std::vector<Tanker::Block> const& blocks() const;
  std::vector<Group> groups() const;
  std::vector<User> const& users() const;

  Tanker::TrustchainId const& trustchainId() const;
  Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey() const;

private:
  struct GroupComparator
  {
    bool operator()(Group const& l, Group const& r) const
    {
      return l.tankerGroup.id < r.tankerGroup.id;
    }
  };

  Tanker::Crypto::SignatureKeyPair _trustchainKeyPair;
  Tanker::TrustchainId _trustchainId;

  std::vector<User> _users;
  std::set<Group, GroupComparator> _groups;
  std::vector<Tanker::Block> _blocks;

  User& getMutableUser(Tanker::SUserId const& suserId);
};
