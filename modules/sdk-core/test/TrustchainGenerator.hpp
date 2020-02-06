
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>

#include <vector>

namespace Tanker::Test
{

struct Device : Users::Device
{
  Crypto::PrivateEncryptionKey privateEncryptionKey;
  Crypto::PrivateSignatureKey privateSignatureKey;
  Trustchain::ClientEntry entry;
  DeviceKeys keys() const;
};

struct User;
class ProvisionalUser;
class Resource;

struct Group
{
  // Group v2
  Group(Trustchain::TrustchainId const& tid,
        Device const& author,
        std::vector<User> const& users,
        std::vector<ProvisionalUser> const& provisionalUsers);

  // Group v1
  Group(Trustchain::TrustchainId const& tid,
        Device const& author,
        std::vector<User> const& users);

  operator Tanker::InternalGroup() const;
  explicit operator Tanker::ExternalGroup() const;
  Trustchain::GroupId const& id() const;
  Crypto::EncryptionKeyPair const& currentEncKp() const;
  Crypto::SignatureKeyPair const& currentSigKp() const;
  Crypto::SealedPrivateSignatureKey encryptedSignatureKey() const;
  Crypto::Hash lastBlockHash() const;

  std::vector<Trustchain::ClientEntry> const& entries() const;

  void addUsers(Device const& author,
                std::vector<User> const& users = {},
                std::vector<ProvisionalUser> const& provisionalUsers = {});

  void addUsersV1(Device const& author, std::vector<User> const& users);

private:
  Trustchain::TrustchainId _tid;
  Crypto::EncryptionKeyPair _currentEncKp;
  Crypto::SignatureKeyPair _currentSigKp;
  Trustchain::GroupId _id;
  std::vector<Trustchain::ClientEntry> _entries;
};

struct User
{
  User(Trustchain::UserId const& id,
       Trustchain::TrustchainId const& tid,
       Crypto::EncryptionKeyPair const& userKeys,
       std::vector<Device> devices);

  User(User const&) = default;
  User& operator=(User const&) = default;
  User(User&&) = default;
  User& operator=(User&&) = default;

  operator Users::User() const;
  operator Users::LocalUser() const;

  Trustchain::UserId const& id() const;
  std::vector<Crypto::EncryptionKeyPair> const& userKeys() const;
  std::vector<Trustchain::ClientEntry> entries() const;
  std::vector<Device> const& devices() const;

  [[nodiscard]] Device makeDevice() const;
  Device const& addDevice();

  Group makeGroup(
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {}) const;

  Trustchain::ClientEntry claim(ProvisionalUser const& provisionalUser) const;

  [[nodiscard]] Crypto::EncryptionKeyPair const& addUserKey();
  void addUserKey(Crypto::EncryptionKeyPair const& userKp);

private:
  Trustchain::UserId _id;
  Trustchain::TrustchainId _tid;
  std::vector<Crypto::EncryptionKeyPair> _userKeys;
  std::vector<Device> _devices;
};

class ProvisionalUser
{
public:
  ProvisionalUser(Identity::TargetType target,
                  std::string value,
                  Crypto::EncryptionKeyPair const& appEncKp,
                  Crypto::EncryptionKeyPair const& tankerEncKp,
                  Crypto::SignatureKeyPair const& appSigKp,
                  Crypto::SignatureKeyPair const& tankerSigKp);
  ProvisionalUser(std::string value);

  operator ProvisionalUsers::PublicUser() const;
  operator ProvisionalUsers::SecretUser() const;
  operator ProvisionalUserKeys() const;

  Crypto::EncryptionKeyPair const& appEncryptionKeyPair() const;
  Crypto::EncryptionKeyPair const& tankerEncryptionKeyPair() const;
  Crypto::SignatureKeyPair const& appSignatureKeyPair() const;
  Crypto::SignatureKeyPair const& tankerSignatureKeyPair() const;

private:
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

  Group makeGroup(
      Device const& author,
      std::vector<User> const& users = {},
      std::vector<ProvisionalUser> const& provisionalUsers = {}) const;

  Group makeGroupV1(Device const& author, std::vector<User> const& users) const;

  static ProvisionalUser makeProvisionalUser(std::string const& email);

  Trustchain::ClientEntry shareWith(Device const& sender,
                                    User const& receiver,
                                    Resource const& res);
  Trustchain::ClientEntry shareWith(Device const& sender,
                                    Group const& receiver,
                                    Resource const& res);
  Trustchain::ClientEntry shareWith(Device const& sender,
                                    ProvisionalUser const& receiver,
                                    Resource const& res);

  Trustchain::Context const& context() const;
  Crypto::SignatureKeyPair const& trustchainSigKp() const;
  static std::vector<Trustchain::ServerEntry> makeEntryList(
      std::vector<Trustchain::ClientEntry> entries);
  std::vector<Trustchain::ServerEntry> makeEntryList(
      std::initializer_list<User const> users) const;

private:
  Crypto::SignatureKeyPair _trustchainKeyPair;
  Trustchain::ServerEntry _rootBlock;
  Trustchain::Context _context;
};
}