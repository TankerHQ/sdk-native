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
    DeviceKeys const& deviceKeys,
    Trustchain::TrustchainId const& tId)
{
  auto const serverEntries = TC_AWAIT(requester->getMe());
  auto const [context, user, userKeys] =
      Updater::processUserEntries(deviceKeys, tId, serverEntries);
  auto const selfDevice =
      user.findDevice(deviceKeys.encryptionKeyPair.publicKey);
  TC_RETURN(std::make_tuple(
      LocalUser(user.id(), selfDevice->id(), deviceKeys, userKeys), context));
}
}

tc::cotask<std::unique_ptr<LocalUserAccessor>> LocalUserAccessor::create(
    Trustchain::UserId const& userId,
    Trustchain::TrustchainId const& trustchainId,
    IRequester* requester,
    std::unique_ptr<LocalUserStore> store)
{
  auto optLocalUser = TC_AWAIT(store->findLocalUser(userId));
  auto optPubKey = TC_AWAIT(store->findTrustchainPublicSignatureKey());
  if (optLocalUser && optPubKey)
    TC_RETURN(std::make_unique<LocalUserAccessor>(
        *optLocalUser,
        Trustchain::Context{trustchainId, *optPubKey},
        requester,
        std::move(store)));
  auto deviceKeys = TC_AWAIT(store->getDeviceKeys());
  auto const [localUser, context] =
      TC_AWAIT(fetchUser(requester, deviceKeys, trustchainId));
  TC_AWAIT(
      store->setTrustchainPublicSignatureKey(context.publicSignatureKey()));
  TC_AWAIT(store->putLocalUser(localUser));

  TC_RETURN(std::make_unique<LocalUserAccessor>(
      localUser, context, requester, std::move(store)));
}

LocalUserAccessor::LocalUserAccessor(
    LocalUser localUser,
    Trustchain::Context context,
    IRequester* requester,
    std::unique_ptr<LocalUserStore> localUserStore)
  : _localUser(std::move(localUser)),
    _context(std::move(context)),
    _requester(requester),
    _store(std::move(localUserStore))
{
}

LocalUserAccessor::~LocalUserAccessor() = default;

tc::cotask<void> LocalUserAccessor::update()
{
  std::tie(_localUser, _context) =
      TC_AWAIT(fetchUser(_requester, _localUser.deviceKeys(), _context.id()));
  TC_AWAIT(_store->putLocalUser(_localUser));
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
