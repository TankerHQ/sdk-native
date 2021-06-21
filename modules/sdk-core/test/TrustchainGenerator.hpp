#pragma once

#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/KeyPublishAction.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserAction.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>

#include <deque>
#include <optional>
#include <vector>

namespace Tanker::Test
{

struct Device : Users::Device
{
  Device(Trustchain::Actions::DeviceCreation action,
         Trustchain::UserId const& uid,
         DeviceKeys const& deviceKeys,
         bool isGhostDevice = true);
  Crypto::PrivateEncryptionKey privateEncryptionKey;
  Crypto::PrivateSignatureKey privateSignatureKey;
  Trustchain::Actions::DeviceCreation action;
  DeviceKeys keys() const;
};

struct User;
class ProvisionalUser;
class Resource;

struct Group
{
  static Group newV1(Trustchain::TrustchainId const& tid,
                     Device const& author,
                     std::vector<User> const& users);
  static Group newV2(Trustchain::TrustchainId const& tid,
                     Device const& author,
                     std::vector<User> const& users,
                     std::vector<ProvisionalUser> const& provisionalUsers);
  static Group newV3(Trustchain::TrustchainId const& tid,
                     Device const& author,
                     std::vector<User> const& users,
                     std::vector<ProvisionalUser> const& provisionalUsers);

  operator Tanker::InternalGroup() const;
  explicit operator Tanker::ExternalGroup() const;
  Trustchain::GroupId const& id() const;
  Crypto::EncryptionKeyPair const& currentEncKp() const;
  Crypto::SignatureKeyPair const& currentSigKp() const;
  Crypto::SealedPrivateSignatureKey encryptedSignatureKey() const;
  Crypto::Hash lastBlockHash() const;
  Crypto::Hash lastKeyRotationBlockHash() const;

  std::vector<Trustchain::GroupAction> const& entries() const;

  Trustchain::Actions::UserGroupAddition addUsersV1(
      Device const& author, std::vector<User> const& users);
  Trustchain::Actions::UserGroupAddition addUsersV2(
      Device const& author,
      std::vector<User> const& newUsers = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {});
  Trustchain::Actions::UserGroupAddition addUsers(
      Device const& author,
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {});
  Trustchain::Actions::UserGroupUpdate updateUsers(
      Device const& author,
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {});

private:
  Group(Trustchain::TrustchainId const& tid,
        Device const& author,
        Crypto::EncryptionKeyPair const& currentEncKp,
        Crypto::SignatureKeyPair const& currentSigKp,
        std::vector<Trustchain::GroupAction> const& entries,
        Crypto::Hash const& lastKeyRotationBlockHash);

private:
  Trustchain::TrustchainId _tid;
  Crypto::EncryptionKeyPair _currentEncKp;
  Crypto::SignatureKeyPair _currentSigKp;
  Trustchain::GroupId _id;
  std::vector<Trustchain::GroupAction> _entries;
  Crypto::Hash _lastKeyRotationBlockHash;
};

struct User
{
  User(Trustchain::UserId const& id,
       Trustchain::TrustchainId const& tid,
       std::optional<Crypto::EncryptionKeyPair> userKey,
       gsl::span<Device const> devices);

  User(User const&) = default;
  User& operator=(User const&) = default;
  User(User&&) = default;
  User& operator=(User&&) = default;

  operator Users::User() const;
  operator Users::LocalUser() const;

  Trustchain::UserId const& id() const;
  std::vector<Crypto::EncryptionKeyPair> const& userKeys() const;
  /// this does not contains revocation entries
  std::vector<Trustchain::Actions::DeviceCreation> entries() const;
  std::deque<Device> const& devices() const;
  std::deque<Device>& devices();
  Trustchain::Actions::DeviceRevocation2 revokeDevice(Device& target);
  Trustchain::Actions::DeviceRevocation1 revokeDeviceV1(Device& target);
  Trustchain::Actions::DeviceRevocation2 revokeDeviceForMigration(
      Device const& sender, Device& target);

  [[nodiscard]] Device makeDevice() const;
  Device& addDevice();

  [[nodiscard]] Device makeDeviceV1() const;
  Device& addDeviceV1();

  Group makeGroup(
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {}) const;

  Trustchain::Actions::ProvisionalIdentityClaim claim(
      ProvisionalUser const& provisionalUser) const;

  Crypto::EncryptionKeyPair const& addUserKey();
  void addUserKey(Crypto::EncryptionKeyPair const& userKp);

private:
  Trustchain::UserId _id;
  Trustchain::TrustchainId _tid;
  std::vector<Crypto::EncryptionKeyPair> _userKeys;
  std::deque<Device> _devices;
};

class ProvisionalUser
{

public:
  ProvisionalUser(Trustchain::TrustchainId const& tid, std::string value);

  operator ProvisionalUsers::PublicUser() const;
  operator ProvisionalUsers::SecretUser() const;
  operator ProvisionalUserKeys() const;
  operator Identity::SecretProvisionalIdentity() const;

  Crypto::EncryptionKeyPair const& appEncryptionKeyPair() const;
  Crypto::EncryptionKeyPair const& tankerEncryptionKeyPair() const;
  Crypto::SignatureKeyPair const& appSignatureKeyPair() const;
  Crypto::SignatureKeyPair const& tankerSignatureKeyPair() const;

private:
  Trustchain::TrustchainId _tid;
  Identity::TargetType _target;
  std::string _value;
  Crypto::EncryptionKeyPair _appEncKp;
  Crypto::EncryptionKeyPair _tankerEncKp;
  Crypto::SignatureKeyPair _appSigKp;
  Crypto::SignatureKeyPair _tankerSigKp;
};

class Resource
{
public:
  inline auto const& id() const
  {
    return _rid;
  }

  inline auto const& key() const
  {
    return _key;
  }

  Resource();
  Resource(Trustchain::ResourceId const& id, Crypto::SymmetricKey const& key);
  [[nodiscard]] bool operator==(Resource const& rhs) const noexcept;

  Resource(Resource const&) = delete;
  Resource(Resource&&) = delete;
  Resource& operator=(Resource const&) = delete;
  Resource& operator=(Resource&&) = delete;

private:
  Trustchain::ResourceId _rid;
  Crypto::SymmetricKey _key;
};

class Generator
{
public:
  Generator();

  User makeUser(std::string const& suserId) const;
  User makeUserV1(std::string const& suserId) const;

  Group makeGroupV1(Device const& author, std::vector<User> const& users) const;
  Group makeGroupV2(
      Device const& author,
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {}) const;
  Group makeGroup(
      Device const& author,
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {}) const;

  ProvisionalUser makeProvisionalUser(std::string const& email);

  Trustchain::Actions::KeyPublishToUser shareWith(Device const& sender,
                                                  User const& receiver,
                                                  Resource const& res);
  Trustchain::Actions::KeyPublishToUserGroup shareWith(Device const& sender,
                                                       Group const& receiver,
                                                       Resource const& res);
  Trustchain::Actions::KeyPublishToProvisionalUser shareWith(
      Device const& sender,
      ProvisionalUser const& receiver,
      Resource const& res);

  Trustchain::Context const& context() const;
  Trustchain::Actions::TrustchainCreation const& rootBlock() const;
  Crypto::SignatureKeyPair const& trustchainSigKp() const;
  // This does not contain revocation entries
  static std::vector<Trustchain::Actions::DeviceCreation> makeEntryList(
      std::initializer_list<Device> devices);
  std::vector<Trustchain::UserAction> makeEntryList(
      std::initializer_list<User> users) const;

private:
  Crypto::SignatureKeyPair _trustchainKeyPair;
  Trustchain::Actions::TrustchainCreation _rootBlock;
  Trustchain::Context _context;
};
}
