#include "TrustchainGenerator.hpp"

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

#include <Helpers/Entries.hpp>
#include <Helpers/TransformTo.hpp>

#include <functional>
#include <iterator>

namespace Tanker::Test
{
// ============ Device

namespace
{
Device createFirstDevice(Trustchain::TrustchainId const& tid,
                         Trustchain::UserId const& uid,
                         Crypto::EncryptionKeyPair const& userKeys,
                         Crypto::PrivateSignatureKey const& authorSKey)
{
  auto const deviceKeys = DeviceKeys::create();
  auto const entry =
      Users::createNewUserEntry(tid,
                                Identity::makeDelegation(uid, authorSKey),
                                deviceKeys.signatureKeyPair.publicKey,
                                deviceKeys.encryptionKeyPair.publicKey,
                                userKeys);
  return {entry, uid, deviceKeys, true};
}

Device createDeviceV1(Trustchain::TrustchainId const& tid,
                      Trustchain::UserId const& uid,
                      Crypto::Hash const& author,
                      Crypto::PrivateSignatureKey const& authorSKey)
{
  auto const deviceKeys = DeviceKeys::create();
  auto const entry =
      Users::createDeviceV1Entry(tid,
                                 author,
                                 Identity::makeDelegation(uid, authorSKey),
                                 deviceKeys.signatureKeyPair.publicKey,
                                 deviceKeys.encryptionKeyPair.publicKey);
  return {entry, uid, deviceKeys, false};
}

Device createDevice(Trustchain::TrustchainId const& tid,
                    Trustchain::UserId const& uid,
                    Crypto::EncryptionKeyPair const& userKeys,
                    Device const& authorDevice)
{
  auto const deviceKeys = DeviceKeys::create();
  auto const entry = Users::createNewDeviceEntry(
      tid,
      authorDevice.id(),
      Identity::makeDelegation(uid,
                               authorDevice.keys().signatureKeyPair.privateKey),
      deviceKeys.signatureKeyPair.publicKey,
      deviceKeys.encryptionKeyPair.publicKey,
      userKeys);
  return {entry, uid, deviceKeys, false};
}
}

Device::Device(Trustchain::ClientEntry entry,
               Trustchain::UserId const& uid,
               DeviceKeys const& deviceKeys,
               bool isGhostDevice)
  : Users::Device(static_cast<Trustchain::DeviceId>(entry.hash()),
                  uid,
                  deviceKeys.signatureKeyPair.publicKey,
                  deviceKeys.encryptionKeyPair.publicKey,
                  isGhostDevice),
    privateEncryptionKey(deviceKeys.encryptionKeyPair.privateKey),
    privateSignatureKey(deviceKeys.signatureKeyPair.privateKey),
    entry(std::move(entry))
{
}

DeviceKeys Device::keys() const
{
  return DeviceKeys{{publicSignatureKey(), privateSignatureKey},
                    {publicEncryptionKey(), privateEncryptionKey}};
}

// ============ Users

User::User(Trustchain::UserId const& id,
           Trustchain::TrustchainId const& tid,
           std::optional<Crypto::EncryptionKeyPair> userKey,
           gsl::span<Device const> devices)
  : _id(id), _tid(tid), _devices(std::begin(devices), std::end(devices))
{
  if (userKey)
    _userKeys.push_back(*userKey);
}

User::operator Users::User() const
{
  return Users::User(id(),
                     (userKeys().size() > 0) ?
                         std::make_optional(userKeys().back().publicKey) :
                         std::nullopt,
                     transformTo<std::vector<Users::Device>>(devices()));
}

User::operator Users::LocalUser() const
{
  auto const& firstDevice = devices().front();
  return Users::LocalUser(
      id(), firstDevice.id(), firstDevice.keys(), userKeys());
}

Group User::makeGroup(
    std::vector<User> const& users,
    std::vector<ProvisionalUser> const& provisionalUsers) const
{
  std::vector<User> withMe({*this});
  withMe.reserve(withMe.size() + users.size());
  withMe.insert(withMe.end(), std::begin(users), std::end(users));
  return {_tid, devices().back(), withMe, provisionalUsers};
}

Device User::makeDevice() const
{
  return createDevice(_tid, id(), userKeys().back(), _devices.front());
}

Device& User::addDevice()
{
  return _devices.emplace_back(makeDevice());
}

Device User::makeDeviceV1() const
{
  return createDeviceV1(_tid,
                        id(),
                        Crypto::Hash{_devices.front().id()},
                        _devices.front().keys().signatureKeyPair.privateKey);
}

Device& User::addDeviceV1()
{
  return _devices.emplace_back(makeDeviceV1());
}

Trustchain::ClientEntry User::claim(
    ProvisionalUser const& provisionalUser) const
{
  auto const& lastDevice = devices().back();
  return Users::createProvisionalIdentityClaimEntry(
      _tid,
      lastDevice.id(),
      lastDevice.keys().signatureKeyPair.privateKey,
      id(),
      provisionalUser,
      userKeys().back());
}

Trustchain::UserId const& User::id() const
{
  return _id;
}

std::vector<Crypto::EncryptionKeyPair> const& User::userKeys() const
{
  return _userKeys;
}

Crypto::EncryptionKeyPair const& User::addUserKey()
{
  return _userKeys.emplace_back(Crypto::makeEncryptionKeyPair());
}

void User::addUserKey(Crypto::EncryptionKeyPair const& userKp)
{
  _userKeys.push_back(userKp);
}

/// this does not contains revocation entries
std::vector<Trustchain::ClientEntry> User::entries() const
{
  return transformTo<std::vector<Trustchain::ClientEntry>>(
      devices(), [](auto&& device) { return device.entry; });
}

std::deque<Device> const& User::devices() const
{
  return _devices;
}

std::deque<Device>& User::devices()
{
  return _devices;
}

Trustchain::ClientEntry User::revokeDevice(Device& target)
{
  auto const newUserKey = Crypto::makeEncryptionKeyPair();
  target.setRevoked();
  auto entry = Revocation::makeRevokeDeviceEntry(
      target.id(),
      _tid,
      *this,
      transformTo<std::vector<Users::Device>>(devices()),
      newUserKey);
  addUserKey(newUserKey);
  return entry;
}

Trustchain::ClientEntry User::revokeDeviceV1(Device& target)
{
  target.setRevoked();
  auto const& source = devices().front();
  return Users::revokeDeviceV1Entry(_tid,
                                    source.id(),
                                    source.keys().signatureKeyPair.privateKey,
                                    target.id());
}

Trustchain::ClientEntry User::revokeDeviceForMigration(Device const& sender,
                                                       Device& target)
{
  auto const user = Users::User{*this};
  assert(user.findDevice(sender.id()));
  assert(user.findDevice(target.id()));
  assert(userKeys().empty());

  auto const newUserKey = Crypto::makeEncryptionKeyPair();
  auto const userKeys = Revocation::encryptPrivateKeyForDevices(
      user.devices(), sender.id(), newUserKey.privateKey);
  auto const entry =
      Users::revokeDeviceEntry(_tid,
                               sender.id(),
                               sender.keys().signatureKeyPair.privateKey,
                               target.id(),
                               newUserKey.publicKey,
                               {},
                               {},
                               userKeys);
  addUserKey(newUserKey);
  target.setRevoked();
  return entry;
}

// ============ Groups
namespace
{
auto createGroupEntry(Trustchain::TrustchainId const& tid,
                      Device const& author,
                      Crypto::EncryptionKeyPair const& encKp,
                      Crypto::SignatureKeyPair const& sigKp,
                      std::vector<User> const& users,
                      std::vector<ProvisionalUser> const& provisionalUsers)
{
  return Groups::Manager::makeUserGroupCreationEntry(
      transformTo<std::vector<Users::User>>(users),
      transformTo<std::vector<ProvisionalUsers::PublicUser>>(provisionalUsers),
      sigKp,
      encKp,
      tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey);
}

using SealedPrivateEncryptionKeysForUsers = Trustchain::Actions::
    UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers;

SealedPrivateEncryptionKeysForUsers generateGroupKeysForUsers(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<User> const& users)
{
  SealedPrivateEncryptionKeysForUsers keysForUsers;
  for (auto const& user : users)
  {
    if (user.userKeys().empty())
      throw std::runtime_error(
          "TrustchainGenerator: can't add a user without user key to a "
          "group");
    keysForUsers.emplace_back(
        user.userKeys().back().publicKey,
        Crypto::sealEncrypt(groupPrivateEncryptionKey,
                            user.userKeys().back().publicKey));
  }
  return keysForUsers;
}

auto createGroupEntry(Trustchain::TrustchainId const& tid,
                      Device const& author,
                      Crypto::EncryptionKeyPair const& encKp,
                      Crypto::SignatureKeyPair const& sigKp,
                      std::vector<User> const& users)
{
  auto const keysForUsers = generateGroupKeysForUsers(encKp.privateKey, users);
  return Groups::createUserGroupCreationV1Entry(
      sigKp,
      encKp.publicKey,
      keysForUsers,
      tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey);
}
}

Group::Group(Trustchain::TrustchainId const& tid,
             Device const& author,
             std::vector<User> const& users,
             std::vector<ProvisionalUser> const& provisionalUsers)
  : _tid(tid),
    _currentEncKp(Crypto::makeEncryptionKeyPair()),
    _currentSigKp(Crypto::makeSignatureKeyPair()),
    _id(Trustchain::GroupId(_currentSigKp.publicKey)),
    _entries({createGroupEntry(
        tid, author, _currentEncKp, _currentSigKp, users, provisionalUsers)})
{
}

Group::Group(Trustchain::TrustchainId const& tid,
             Device const& author,
             std::vector<User> const& users)
  : _tid(tid),
    _currentEncKp(Crypto::makeEncryptionKeyPair()),
    _currentSigKp(Crypto::makeSignatureKeyPair()),
    _id(Trustchain::GroupId(_currentSigKp.publicKey)),
    _entries(
        {createGroupEntry(tid, author, _currentEncKp, _currentSigKp, users)})
{
}

Trustchain::GroupId const& Group::id() const
{
  return _id;
}

Crypto::EncryptionKeyPair const& Group::currentEncKp() const
{
  return _currentEncKp;
}

Crypto::SignatureKeyPair const& Group::currentSigKp() const
{
  return _currentSigKp;
}

Crypto::SealedPrivateSignatureKey Group::encryptedSignatureKey() const
{
  return Crypto::sealEncrypt(currentSigKp().privateKey,
                             currentEncKp().publicKey);
}

Crypto::Hash Group::lastBlockHash() const
{
  return entries().back().hash();
}

std::vector<Trustchain::ClientEntry> const& Group::entries() const
{
  return _entries;
}

Group::operator Tanker::InternalGroup() const
{
  return {
      id(),
      currentSigKp(),
      currentEncKp(),
      lastBlockHash(),
  };
}

Group::operator Tanker::ExternalGroup() const
{
  return {
      id(),
      currentSigKp().publicKey,
      encryptedSignatureKey(),
      currentEncKp().publicKey,
      lastBlockHash(),
  };
}

Trustchain::ClientEntry const& Group::addUsers(
    Device const& author,
    std::vector<User> const& newUsers,
    std::vector<ProvisionalUser> const& provisionalUsers)
{
  return _entries.emplace_back(Groups::Manager::makeUserGroupAdditionEntry(
      transformTo<std::vector<Users::User>>(newUsers),
      transformTo<std::vector<ProvisionalUsers::PublicUser>>(provisionalUsers),
      *this,
      _tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey));
}

Trustchain::ClientEntry const& Group::addUsersV1(Device const& author,
                                                 std::vector<User> const& users)
{
  auto const keysForUsers =
      generateGroupKeysForUsers(currentEncKp().privateKey, users);

  return _entries.emplace_back(Groups::createUserGroupAdditionV1Entry(
      currentSigKp(),
      lastBlockHash(),
      keysForUsers,
      _tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey));
}

// ================ ProvisionalUser

ProvisionalUser::ProvisionalUser(Trustchain::TrustchainId const& tid,
                                 std::string email)

  : _tid(tid),
    _target(Identity::TargetType::Email),
    _value(std::move(email)),
    _appEncKp(Crypto::makeEncryptionKeyPair()),
    _tankerEncKp(Crypto::makeEncryptionKeyPair()),
    _appSigKp(Crypto::makeSignatureKeyPair()),
    _tankerSigKp(Crypto::makeSignatureKeyPair())
{
}

Crypto::EncryptionKeyPair const& ProvisionalUser::appEncryptionKeyPair() const
{
  return _appEncKp;
}

Crypto::EncryptionKeyPair const& ProvisionalUser::tankerEncryptionKeyPair()
    const
{
  return _tankerEncKp;
}

Crypto::SignatureKeyPair const& ProvisionalUser::appSignatureKeyPair() const
{
  return _appSigKp;
}

Crypto::SignatureKeyPair const& ProvisionalUser::tankerSignatureKeyPair() const
{
  return _tankerSigKp;
}

ProvisionalUser::operator ProvisionalUsers::PublicUser() const
{
  return {
      appSignatureKeyPair().publicKey,
      appEncryptionKeyPair().publicKey,
      tankerSignatureKeyPair().publicKey,
      tankerEncryptionKeyPair().publicKey,
  };
}

ProvisionalUser::operator ProvisionalUsers::SecretUser() const
{
  return {
      _target,
      _value,
      appEncryptionKeyPair(),
      tankerEncryptionKeyPair(),
      appSignatureKeyPair(),
      tankerSignatureKeyPair(),
  };
}

ProvisionalUser::operator ProvisionalUserKeys() const
{
  return {
      appEncryptionKeyPair(),
      tankerEncryptionKeyPair(),
  };
}

ProvisionalUser::operator Identity::SecretProvisionalIdentity() const
{
  return {_tid, _target, _value, appSignatureKeyPair(), appEncryptionKeyPair()};
}

// ================ Resource

Resource::Resource()
{
  Crypto::randomFill(_rid);
  Crypto::randomFill(_key);
}

Resource::Resource(Trustchain::ResourceId const& id,
                   Crypto::SymmetricKey const& key)
  : _rid(id), _key(key)
{
}

bool Resource::operator==(Resource const& rhs) const noexcept
{
  return std::tie(this->id(), this->key()) == std::tie(rhs.id(), rhs.key());
}

// ================ Generator

namespace
{
using namespace Trustchain;
auto contextFromRootBlock(ServerEntry const& entry)
{
  auto const& tc = entry.action().get<Actions::TrustchainCreation>();
  return Context{entry.trustchainId(), tc.publicSignatureKey()};
}

ServerEntry createRootBlock(Crypto::SignatureKeyPair const& keyPair)
{
  auto const nature = Actions::Nature::TrustchainCreation;
  Crypto::Hash const author{};
  Actions::TrustchainCreation const action{keyPair.publicKey};
  auto const hash =
      computeHash(nature, author, Serialization::serialize(action));
  return {static_cast<TrustchainId>(hash),
          author,
          action,
          hash,
          Crypto::Signature{}};
}
}

Generator::Generator()
  : _trustchainKeyPair(Crypto::makeSignatureKeyPair()),
    _rootBlock(createRootBlock(_trustchainKeyPair)),
    _context(contextFromRootBlock(_rootBlock))
{
}

Trustchain::Context const& Generator::context() const
{
  return _context;
}

Trustchain::ServerEntry const& Generator::rootBlock() const
{
  return _rootBlock;
}

Crypto::SignatureKeyPair const& Generator::trustchainSigKp() const
{
  return _trustchainKeyPair;
}

User Generator::makeUser(std::string const& suserId) const
{
  auto const userId = Tanker::obfuscateUserId(SUserId{suserId}, _context.id());
  auto const userKeys = Crypto::makeEncryptionKeyPair();

  auto const device = createFirstDevice(
      _context.id(), userId, userKeys, _trustchainKeyPair.privateKey);
  return {userId, _context.id(), userKeys, {device}};
}

User Generator::makeUserV1(std::string const& suserId) const
{
  auto const userId = Tanker::obfuscateUserId(SUserId{suserId}, _context.id());

  auto const device = createDeviceV1(context().id(),
                                     userId,
                                     Crypto::Hash{context().id()},
                                     _trustchainKeyPair.privateKey);
  return {userId, context().id(), std::nullopt, {device}};
}

Group Generator::makeGroup(
    Device const& author,
    std::vector<User> const& users,
    std::vector<ProvisionalUser> const& provisionalUsers) const
{
  return {context().id(), author, users, provisionalUsers};
}

Group Generator::makeGroupV1(Device const& author,
                             std::vector<User> const& users) const
{
  return {context().id(), author, users};
}

Trustchain::ClientEntry Generator::shareWith(Device const& sender,
                                             User const& receiver,
                                             Resource const& res)
{
  return Share::makeKeyPublishToUser(context().id(),
                                     sender.id(),
                                     sender.keys().signatureKeyPair.privateKey,
                                     receiver.userKeys().back().publicKey,
                                     res.id(),
                                     res.key());
}

Trustchain::ClientEntry Generator::shareWith(Device const& sender,
                                             Group const& receiver,
                                             Resource const& res)
{
  return Share::makeKeyPublishToGroup(context().id(),
                                      sender.id(),
                                      sender.keys().signatureKeyPair.privateKey,
                                      receiver.currentEncKp().publicKey,
                                      res.id(),
                                      res.key());
}

Trustchain::ClientEntry Generator::shareWith(Device const& sender,
                                             ProvisionalUser const& receiver,
                                             Resource const& res)
{
  return Share::makeKeyPublishToProvisionalUser(
      context().id(),
      sender.id(),
      sender.keys().signatureKeyPair.privateKey,
      receiver,
      res.id(),
      res.key());
}

ProvisionalUser Generator::makeProvisionalUser(std::string const& email)
{
  return {context().id(), email};
}

std::vector<Trustchain::ServerEntry> Generator::makeEntryList(
    std::vector<Trustchain::ClientEntry> const& clientEntries)
{
  auto index = 0ul;
  return transformTo<std::vector<Trustchain::ServerEntry>>(
      clientEntries,
      [&](auto&& e) mutable { return clientToServerEntry(e, ++index); });
}

std::vector<Trustchain::ServerEntry> Generator::makeEntryList(
    std::initializer_list<Device> devices)
{
  std::vector<Trustchain::ServerEntry> entries;
  entries.reserve(devices.size());
  auto index = 0ul;
  std::transform(
      std::begin(devices),
      std::end(devices),
      std::back_inserter(entries),
      [&](auto&& e) { return clientToServerEntry(e.entry, ++index); });
  return entries;
}

std::vector<Trustchain::ServerEntry> Generator::makeEntryList(
    std::initializer_list<User> users) const
{
  std::vector entries{this->_rootBlock};
  auto index = 0ul;
  for (auto&& user : users)
  {
    entries = transformTo<std::vector<Trustchain::ServerEntry>>(
        user.entries(), entries, [&](auto&& e) {
          return clientToServerEntry(e, ++index);
        });
  }
  return entries;
}
}
