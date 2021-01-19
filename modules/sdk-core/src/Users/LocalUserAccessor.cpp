#include <Tanker/Users/LocalUserAccessor.hpp>

#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Users/Updater.hpp>

namespace Tanker::Users
{
namespace
{
tc::cotask<std::tuple<LocalUser, Trustchain::Context>> fetchUser(
    IRequester* requester,
    Trustchain::TrustchainId const& tId,
    Trustchain::UserId const& userId,
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys)
{
  auto const [trustchainCreation, actions] =
      TC_AWAIT(requester->getUsers(gsl::make_span(&userId, 1)));
  auto const [context, user, userKeys] = Updater::processUserEntries(
      deviceId, deviceKeys, tId, trustchainCreation, actions);
  auto const selfDevice = user.findDevice(deviceId);
  TC_RETURN(std::make_tuple(
      LocalUser(user.id(), selfDevice->id(), deviceKeys, userKeys), context));
}
}

tc::cotask<LocalUserAccessor> LocalUserAccessor::create(
    Trustchain::UserId const& userId,
    Trustchain::TrustchainId const& trustchainId,
    IRequester* requester,
    LocalUserStore* store)
{
  auto optLocalUser = TC_AWAIT(store->findLocalUser(userId));
  auto optPubKey = TC_AWAIT(store->findTrustchainPublicSignatureKey());
  if (optLocalUser && optPubKey)
    TC_RETURN(LocalUserAccessor(*optLocalUser,
                                Trustchain::Context{trustchainId, *optPubKey},
                                requester,
                                store));

  auto deviceKeys = TC_AWAIT(store->getDeviceKeys());
  auto deviceId = TC_AWAIT(store->getDeviceId());
  auto const [localUser, context] = TC_AWAIT(
      fetchUser(requester, trustchainId, userId, deviceId, deviceKeys));
  TC_AWAIT(store->initializeDevice(context.publicSignatureKey(),
                                   localUser.userKeys()));

  TC_RETURN(LocalUserAccessor(localUser, context, requester, store));
}

LocalUserAccessor::LocalUserAccessor(LocalUser localUser,
                                     Trustchain::Context context,
                                     IRequester* requester,
                                     LocalUserStore* localUserStore)
  : _localUser(std::move(localUser)),
    _context(std::move(context)),
    _requester(requester),
    _store(localUserStore)
{
}

LocalUserAccessor::~LocalUserAccessor() = default;

tc::cotask<void> LocalUserAccessor::update()
{
  std::tie(_localUser, _context) = TC_AWAIT(fetchUser(_requester,
                                                      _context.id(),
                                                      _localUser.userId(),
                                                      _localUser.deviceId(),
                                                      _localUser.deviceKeys()));
  TC_AWAIT(_store->putUserKeys(_localUser.userKeys()));
}

tc::cotask<void> LocalUserAccessor::confirmRevocation()
{
  auto const& deviceId = _localUser.deviceId();
  auto const& deviceKeys = _localUser.deviceKeys();
  auto const [trustchainCreation, actions] =
      TC_AWAIT(_requester->getRevokedDeviceHistory(_localUser.deviceId()));
  // This will throw if we are effectively revoked
  auto const [context, user, userKeys] = Updater::processUserEntries(
      deviceId, deviceKeys, _context.id(), trustchainCreation, actions);
  auto const selfDevice = user.findDevice(deviceId);
  _localUser = LocalUser(user.id(), selfDevice->id(), deviceKeys, userKeys);
  _context = context;
  TC_AWAIT(_store->putUserKeys(_localUser.userKeys()));
}

Trustchain::Context const& LocalUserAccessor::getContext() const
{
  return _context;
}

tc::cotask<LocalUser const&> LocalUserAccessor::pull()
{
  TC_AWAIT(update());
  TC_RETURN(_localUser);
}

LocalUser const& LocalUserAccessor::get() const
{
  return _localUser;
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
LocalUserAccessor::pullUserKeyPair(
    Crypto::PublicEncryptionKey const& publicUserKey)
{
  auto const optUserKey = _localUser.findKeyPair(publicUserKey);
  if (optUserKey)
    TC_RETURN(optUserKey);
  TC_AWAIT(update());
  TC_RETURN(_localUser.findKeyPair(publicUserKey));
}
}
