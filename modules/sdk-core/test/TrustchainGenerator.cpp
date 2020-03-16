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
#include <Tanker/Users/EntryGenerator.hpp>

#include <Helpers/Entries.hpp>

#include <algorithm>
#include <functional>
#include <iterator>

namespace Tanker::Test
{
namespace
{
template <typename T, typename U, typename F>
std::vector<T> transformTo(std::vector<U> const& source,
                           std::vector<T> init,
                           F&& f)
{
  init.reserve(init.size() + source.size());
  std::transform(std::begin(source),
                 std::end(source),
                 std::back_inserter(init),
                 std::forward<F>(f));
  return init;
}

template <typename T, typename U, typename F>
std::vector<T> transformTo(std::vector<U> const& source, F&& f)
{
  return transformTo<T>(source, std::vector<T>{}, std::forward<F>(f));
}

template <typename T, typename U>
std::vector<T> transformTo(std::vector<U> const& source)
{
  return transformTo<T>(source, [](U const& item) -> T { return item; });
}
}

// ============ Device

namespace
{
Device createDevice(Trustchain::TrustchainId const& id,
                    Trustchain::UserId const& uid,
                    Crypto::EncryptionKeyPair const& userKeys,
                    Crypto::PrivateSignatureKey const& authorSKey)
{
  auto const delegation = Identity::makeDelegation(uid, authorSKey);
  auto const deviceKeys = DeviceKeys::create();
  auto const newUserEntry =
      Users::createNewUserEntry(id,
                                delegation,
                                deviceKeys.signatureKeyPair.publicKey,
                                deviceKeys.encryptionKeyPair.publicKey,
                                userKeys);
  return {Users::Device{static_cast<Trustchain::DeviceId>(newUserEntry.hash()),
                        uid,
                        deviceKeys.signatureKeyPair.publicKey,
                        deviceKeys.encryptionKeyPair.publicKey,
                        true},
          deviceKeys.encryptionKeyPair.privateKey,
          deviceKeys.signatureKeyPair.privateKey,
          std::move(newUserEntry)};
}
}

DeviceKeys Device::keys() const
{
  return DeviceKeys{{publicSignatureKey(), privateSignatureKey},
                    {publicEncryptionKey(), privateEncryptionKey}};
}

// ============ Users

User::User(Trustchain::UserId const& id,
           Trustchain::TrustchainId const& tid,
           Crypto::EncryptionKeyPair const& userKeys,
           std::vector<Device> devices)
  : _id(id), _tid(tid), _userKeys({userKeys}), _devices(std::move(devices))
{
}

User::operator Users::User() const
{
  std::vector<Users::Device> devices;
  devices.reserve(_devices.size());
  std::transform(std::begin(_devices),
                 std::end(_devices),
                 std::back_inserter(devices),
                 [](auto&& d) -> Users::Device { return d; });
  return Users::User(id(), userKeys().back().publicKey, devices);
}

User::operator Users::LocalUser() const
{
  auto const& lastDevice = devices().back();
  return Users::LocalUser(id(), lastDevice.id(), lastDevice.keys(), userKeys());
}

Device User::makeDevice() const
{
  return createDevice(
      _tid, id(), userKeys().back(), _devices.front().privateSignatureKey);
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

Device const& User::addDevice()
{
  return _devices.emplace_back(makeDevice());
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

std::vector<Trustchain::ClientEntry> User::entries() const
{
  std::vector<Trustchain::ClientEntry> entries;
  entries.reserve(_devices.size());
  std::transform(std::begin(_devices),
                 std::end(_devices),
                 std::back_inserter(entries),
                 [](auto&& d) { return d.entry; });
  return entries;
}

std::vector<Device> const& User::devices() const
{
  return _devices;
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
      transformTo<Users::User>(users),
      transformTo<ProvisionalUsers::PublicUser>(provisionalUsers),
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
          "TrustchainGenerator: can't add a user without user key to a group");
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

void Group::addUsers(Device const& author,
                     std::vector<User> const& newUsers,
                     std::vector<ProvisionalUser> const& provisionalUsers)
{
  _entries.push_back(Groups::Manager::makeUserGroupAdditionEntry(
      transformTo<Users::User>(newUsers),
      transformTo<ProvisionalUsers::PublicUser>(provisionalUsers),
      *this,
      _tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey));
}

void Group::addUsersV1(Device const& author, std::vector<User> const& users)
{
  auto const keysForUsers =
      generateGroupKeysForUsers(currentEncKp().privateKey, users);

  auto const clientEntry = Groups::createUserGroupAdditionV1Entry(
      currentSigKp(),
      lastBlockHash(),
      keysForUsers,
      _tid,
      author.id(),
      author.keys().signatureKeyPair.privateKey);
  _entries.push_back(clientEntry);
}

ProvisionalUser::ProvisionalUser(Identity::TargetType target,
                                 std::string value,
                                 Crypto::EncryptionKeyPair const& appEncKp,
                                 Crypto::EncryptionKeyPair const& tankerEncKp,
                                 Crypto::SignatureKeyPair const& appSigKp,
                                 Crypto::SignatureKeyPair const& tankerSigKp)
  : _target(target),
    _value(std::move(value)),
    _appEncKp(appEncKp),
    _tankerEncKp(tankerEncKp),
    _appSigKp(appSigKp),
    _tankerSigKp(tankerSigKp)
{
}

ProvisionalUser::ProvisionalUser(std::string email)
  : ProvisionalUser(Identity::TargetType::Email,
                    std::move(email),
                    Crypto::makeEncryptionKeyPair(),
                    Crypto::makeEncryptionKeyPair(),
                    Crypto::makeSignatureKeyPair(),
                    Crypto::makeSignatureKeyPair())
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
          1,
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

Crypto::SignatureKeyPair const& Generator::trustchainSigKp() const
{
  return _trustchainKeyPair;
}

User Generator::makeUser(std::string const& suserId) const
{
  auto const userId = Tanker::obfuscateUserId(SUserId{suserId}, _context.id());
  auto const userKeys = Crypto::makeEncryptionKeyPair();

  auto const device = createDevice(
      _context.id(), userId, userKeys, _trustchainKeyPair.privateKey);
  return {userId, _context.id(), userKeys, {device}};
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
  return {email};
}

std::vector<Trustchain::ServerEntry> Generator::makeEntryList(
    std::vector<Trustchain::ClientEntry> clientEntries)
{
  auto index = 0ul;
  return transformTo<Trustchain::ServerEntry>(
      clientEntries,
      [&](auto&& e) mutable { return clientToServerEntry(e, ++index); });
}

std::vector<Trustchain::ServerEntry> Generator::makeEntryList(
    std::initializer_list<User const> users) const
{
  std::vector entries{this->_rootBlock};
  auto index = 0ul;
  for (auto const& user : users)
    entries = transformTo<Trustchain::ServerEntry>(
        user.entries(), entries, [&](auto&& e) mutable {
          return clientToServerEntry(e, ++index);
        });
  return entries;
}
}