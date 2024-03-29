#include "TrustchainGenerator.hpp"

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/ComputeHash.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

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
  auto const action = Users::createNewUserAction(tid,
                                                 Identity::makeDelegation(uid, authorSKey),
                                                 deviceKeys.signatureKeyPair.publicKey,
                                                 deviceKeys.encryptionKeyPair.publicKey,
                                                 userKeys);
  return {action, uid, deviceKeys, true};
}

Device createDeviceV1(Trustchain::TrustchainId const& tid,
                      Trustchain::UserId const& uid,
                      Crypto::Hash const& author,
                      Crypto::PrivateSignatureKey const& authorSKey)
{
  auto const deviceKeys = DeviceKeys::create();
  auto const action = Users::createDeviceV1Action(tid,
                                                  author,
                                                  Identity::makeDelegation(uid, authorSKey),
                                                  deviceKeys.signatureKeyPair.publicKey,
                                                  deviceKeys.encryptionKeyPair.publicKey);
  return {action, uid, deviceKeys, false};
}

Device createDevice(Trustchain::TrustchainId const& tid,
                    Trustchain::UserId const& uid,
                    Crypto::EncryptionKeyPair const& userKeys,
                    Device const& authorDevice)
{
  auto const deviceKeys = DeviceKeys::create();
  auto const action =
      Users::createNewDeviceAction(tid,
                                   authorDevice.id(),
                                   Identity::makeDelegation(uid, authorDevice.keys().signatureKeyPair.privateKey),
                                   deviceKeys.signatureKeyPair.publicKey,
                                   deviceKeys.encryptionKeyPair.publicKey,
                                   userKeys);
  return {action, uid, deviceKeys, false};
}
}

Device::Device(Trustchain::Actions::DeviceCreation action,
               Trustchain::UserId const& uid,
               DeviceKeys const& deviceKeys,
               bool isGhostDevice)
  : Users::Device(static_cast<Trustchain::DeviceId>(action.hash()),
                  uid,
                  deviceKeys.signatureKeyPair.publicKey,
                  deviceKeys.encryptionKeyPair.publicKey,
                  isGhostDevice),
    privateEncryptionKey(deviceKeys.encryptionKeyPair.privateKey),
    privateSignatureKey(deviceKeys.signatureKeyPair.privateKey),
    action(std::move(action))
{
}

DeviceKeys Device::keys() const
{
  return DeviceKeys{{publicSignatureKey(), privateSignatureKey}, {publicEncryptionKey(), privateEncryptionKey}};
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
                     (userKeys().size() > 0) ? std::make_optional(userKeys().back().publicKey) : std::nullopt,
                     devices() | ranges::to<std::vector<Users::Device>>);
}

User::operator Users::LocalUser() const
{
  auto const& firstDevice = devices().front();
  return Users::LocalUser(id(), firstDevice.id(), firstDevice.keys(), userKeys());
}

Group User::makeGroup(std::vector<User> const& users, std::vector<ProvisionalUser> const& provisionalUsers) const
{
  std::vector<User> withMe({*this});
  withMe.reserve(withMe.size() + users.size());
  withMe.insert(withMe.end(), std::begin(users), std::end(users));
  return Group::newV3(_tid, devices().back(), withMe, provisionalUsers);
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
  return createDeviceV1(
      _tid, id(), Crypto::Hash{_devices.front().id()}, _devices.front().keys().signatureKeyPair.privateKey);
}

Device& User::addDeviceV1()
{
  return _devices.emplace_back(makeDeviceV1());
}

Trustchain::Actions::ProvisionalIdentityClaim User::claim(ProvisionalUser const& provisionalUser) const
{
  auto const& lastDevice = devices().back();
  return Users::createProvisionalIdentityClaimAction(
      _tid, lastDevice.id(), lastDevice.keys().signatureKeyPair.privateKey, id(), provisionalUser, userKeys().back());
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

std::vector<Trustchain::Actions::DeviceCreation> User::entries() const
{
  return devices() | ranges::views::transform(&Device::action) | ranges::to<std::vector>;
}

std::deque<Device> const& User::devices() const
{
  return _devices;
}

std::deque<Device>& User::devices()
{
  return _devices;
}

// ============ Groups
namespace
{
auto createGroupActionV1(Trustchain::TrustchainId const& tid,
                         Device const& author,
                         Crypto::EncryptionKeyPair const& encKp,
                         Crypto::SignatureKeyPair const& sigKp,
                         std::vector<User> const& users)
{
  auto const keysForUsers =
      Groups::generateGroupKeysForUsers1(encKp.privateKey, users | ranges::to<std::vector<Users::User>>);
  return Groups::createUserGroupCreationV1Action(
      sigKp, encKp.publicKey, keysForUsers, tid, author.id(), author.keys().signatureKeyPair.privateKey);
}

auto createGroupActionV2(Trustchain::TrustchainId const& tid,
                         Device const& author,
                         Crypto::EncryptionKeyPair const& encKp,
                         Crypto::SignatureKeyPair const& sigKp,
                         std::vector<User> const& users,
                         std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto groupMembers =
      Groups::generateGroupKeysForUsers2(encKp.privateKey, users | ranges::to<std::vector<Users::User>>);
  auto groupProvisionalMembers = Groups::generateGroupKeysForProvisionalUsers2(
      encKp.privateKey, provisionalUsers | ranges::to<std::vector<ProvisionalUsers::PublicUser>>);

  return Groups::createUserGroupCreationV2Action(sigKp,
                                                 encKp.publicKey,
                                                 groupMembers,
                                                 groupProvisionalMembers,
                                                 tid,
                                                 author.id(),
                                                 author.keys().signatureKeyPair.privateKey);
}

auto createGroupActionV3(Trustchain::TrustchainId const& tid,
                         Device const& author,
                         Crypto::EncryptionKeyPair const& encKp,
                         Crypto::SignatureKeyPair const& sigKp,
                         std::vector<User> const& users,
                         std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto groupMembers =
      Groups::generateGroupKeysForUsers2(encKp.privateKey, users | ranges::to<std::vector<Users::User>>);
  auto groupProvisionalMembers = Groups::generateGroupKeysForProvisionalUsers3(
      encKp.privateKey, provisionalUsers | ranges::to<std::vector<ProvisionalUsers::PublicUser>>);

  return Groups::createUserGroupCreationV3Action(sigKp,
                                                 encKp.publicKey,
                                                 groupMembers,
                                                 groupProvisionalMembers,
                                                 tid,
                                                 author.id(),
                                                 author.keys().signatureKeyPair.privateKey);
}
}

Group::Group(Trustchain::TrustchainId const& tid,
             Device const& author,
             Crypto::EncryptionKeyPair const& currentEncKp,
             Crypto::SignatureKeyPair const& currentSigKp,
             std::vector<Trustchain::GroupAction> const& entries,
             Crypto::Hash const& lastKeyRotationBlockHash)
  : _tid(tid),
    _currentEncKp(currentEncKp),
    _currentSigKp(currentSigKp),
    _id(Trustchain::GroupId(_currentSigKp.publicKey)),
    _entries(entries),
    _lastKeyRotationBlockHash(lastKeyRotationBlockHash)
{
}

Group Group::newV1(Trustchain::TrustchainId const& tid, Device const& author, std::vector<User> const& users)
{
  auto currentEncKp = Crypto::makeEncryptionKeyPair();
  auto currentSigKp = Crypto::makeSignatureKeyPair();
  auto entry = createGroupActionV1(tid, author, currentEncKp, currentSigKp, users);
  return Group{tid, author, currentEncKp, currentSigKp, {entry}, Trustchain::getHash(entry)};
}

Group Group::newV2(Trustchain::TrustchainId const& tid,
                   Device const& author,
                   std::vector<User> const& users,
                   std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto currentEncKp = Crypto::makeEncryptionKeyPair();
  auto currentSigKp = Crypto::makeSignatureKeyPair();
  auto entry = createGroupActionV2(tid, author, currentEncKp, currentSigKp, users, provisionalUsers);
  return Group{tid, author, currentEncKp, currentSigKp, {entry}, Trustchain::getHash(entry)};
}

Group Group::newV3(Trustchain::TrustchainId const& tid,
                   Device const& author,
                   std::vector<User> const& users,
                   std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto currentEncKp = Crypto::makeEncryptionKeyPair();
  auto currentSigKp = Crypto::makeSignatureKeyPair();
  auto entry = createGroupActionV3(tid, author, currentEncKp, currentSigKp, users, provisionalUsers);
  return Group{tid, author, currentEncKp, currentSigKp, {entry}, Trustchain::getHash(entry)};
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
  return Crypto::sealEncrypt(currentSigKp().privateKey, currentEncKp().publicKey);
}

Crypto::Hash Group::lastBlockHash() const
{
  return Trustchain::getHash(entries().back());
}

Crypto::Hash Group::lastKeyRotationBlockHash() const
{
  return _lastKeyRotationBlockHash;
}

std::vector<Trustchain::GroupAction> const& Group::entries() const
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
      lastKeyRotationBlockHash(),
  };
}

Group::operator Tanker::ExternalGroup() const
{
  return {id(),
          currentSigKp().publicKey,
          encryptedSignatureKey(),
          currentEncKp().publicKey,
          lastBlockHash(),
          lastKeyRotationBlockHash()};
}

Trustchain::Actions::UserGroupAddition Group::addUsersV1(Device const& author, std::vector<User> const& users)
{
  auto const keysForUsers =
      Groups::generateGroupKeysForUsers1(currentEncKp().privateKey, users | ranges::to<std::vector<Users::User>>);

  auto const groupAddition = Groups::createUserGroupAdditionV1Action(
      currentSigKp(), lastBlockHash(), keysForUsers, _tid, author.id(), author.keys().signatureKeyPair.privateKey);
  _entries.emplace_back(groupAddition);
  return groupAddition;
}

Trustchain::Actions::UserGroupAddition Group::addUsersV2(Device const& author,
                                                         std::vector<User> const& newUsers,
                                                         std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto members =
      Groups::generateGroupKeysForUsers2(currentEncKp().privateKey, newUsers | ranges::to<std::vector<Users::User>>);
  auto provisionalMembers = Groups::generateGroupKeysForProvisionalUsers2(
      currentEncKp().privateKey, provisionalUsers | ranges::to<std::vector<ProvisionalUsers::PublicUser>>);

  auto const groupAddition = Groups::createUserGroupAdditionV2Action(currentSigKp(),
                                                                     lastBlockHash(),
                                                                     members,
                                                                     provisionalMembers,
                                                                     _tid,
                                                                     author.id(),
                                                                     author.keys().signatureKeyPair.privateKey);
  _entries.emplace_back(groupAddition);
  return groupAddition;
}

Trustchain::Actions::UserGroupAddition Group::addUsers(Device const& author,
                                                       std::vector<User> const& newUsers,
                                                       std::vector<ProvisionalUser> const& provisionalUsers)
{
  auto const groupAddition = Groups::Manager::makeUserGroupAdditionAction(
      newUsers | ranges::to<std::vector<Users::User>>,
      provisionalUsers | ranges::to<std::vector<ProvisionalUsers::PublicUser>>,
      *this,
      _tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey);
  _entries.emplace_back(groupAddition);
  return groupAddition;
}

// ================ ProvisionalUser

ProvisionalUser::ProvisionalUser(Trustchain::TrustchainId const& tid, std::string email)

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

Crypto::EncryptionKeyPair const& ProvisionalUser::tankerEncryptionKeyPair() const
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

Resource::Resource(Crypto::SimpleResourceId const& id, Crypto::SymmetricKey const& key) : _rid(id), _key(key)
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
auto contextFromRootBlock(Actions::TrustchainCreation const& tc)
{
  return Context{TrustchainId{tc.hash()}, tc.publicSignatureKey()};
}
}

Generator::Generator()
  : _trustchainKeyPair(Crypto::makeSignatureKeyPair()),
    _rootBlock(Actions::TrustchainCreation{_trustchainKeyPair.publicKey}),
    _context(contextFromRootBlock(_rootBlock))
{
}

Trustchain::Context const& Generator::context() const
{
  return _context;
}

Trustchain::Actions::TrustchainCreation const& Generator::rootBlock() const
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

  auto const device = createFirstDevice(_context.id(), userId, userKeys, _trustchainKeyPair.privateKey);
  return {userId, _context.id(), userKeys, std::vector{device}};
}

User Generator::makeUserV1(std::string const& suserId) const
{
  auto const userId = Tanker::obfuscateUserId(SUserId{suserId}, _context.id());

  auto const device =
      createDeviceV1(context().id(), userId, Crypto::Hash{context().id()}, _trustchainKeyPair.privateKey);
  return {userId, context().id(), std::nullopt, std::vector{device}};
}

Group Generator::makeGroupV1(Device const& author, std::vector<User> const& users) const
{
  return Group::newV1(context().id(), author, users);
}

Group Generator::makeGroupV2(Device const& author,
                             std::vector<User> const& users,
                             std::vector<ProvisionalUser> const& provisionalUsers) const
{
  return Group::newV2(context().id(), author, users, provisionalUsers);
}

Group Generator::makeGroup(Device const& author,
                           std::vector<User> const& users,
                           std::vector<ProvisionalUser> const& provisionalUsers) const
{
  return Group::newV3(context().id(), author, users, provisionalUsers);
}

Trustchain::Actions::KeyPublishToUser Generator::shareWith(Device const& sender,
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

Trustchain::Actions::KeyPublishToUserGroup Generator::shareWith(Device const& sender,
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

Trustchain::Actions::KeyPublishToProvisionalUser Generator::shareWith(Device const& sender,
                                                                      ProvisionalUser const& receiver,
                                                                      Resource const& res)
{
  return Share::makeKeyPublishToProvisionalUser(
      context().id(), sender.id(), sender.keys().signatureKeyPair.privateKey, receiver, res.id(), res.key());
}

ProvisionalUser Generator::makeProvisionalUser(std::string const& email)
{
  return {context().id(), email};
}

std::vector<Trustchain::Actions::DeviceCreation> Generator::makeEntryList(std::initializer_list<Device> devices)
{
  return devices | ranges::views::transform(&Device::action) | ranges::to<std::vector>;
}

std::vector<Trustchain::UserAction> Generator::makeEntryList(std::initializer_list<User> users) const
{
  std::vector<Trustchain::UserAction> entries;
  for (auto&& user : users)
  {
    auto const& userEntries = user.entries();
    entries.insert(entries.end(), userEntries.begin(), userEntries.end());
  }
  return entries;
}
}
