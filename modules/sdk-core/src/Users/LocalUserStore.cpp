#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Users/LocalUser.hpp>

TLOG_CATEGORY(LocalUserStore);

namespace Tanker::Users
{

LocalUserStore::LocalUserStore(DataStore::ADatabase* db) : _dbCon(db)
{
}

tc::cotask<void> LocalUserStore::putLocalUser(LocalUser const& user)
{
  if (!TC_AWAIT(_dbCon->getDeviceId()))
    TC_AWAIT(_dbCon->setDeviceId(user.deviceId()));
  TC_AWAIT(putUserKeys(user.userKeys()));
}

tc::cotask<void> LocalUserStore::putUserKeys(
    gsl::span<Crypto::EncryptionKeyPair const> userKeys)
{
  TC_AWAIT(_dbCon->putUserKeyPairs(userKeys));
}

tc::cotask<DeviceKeys> LocalUserStore::getDeviceKeys() const
{
  if (auto const keys = TC_AWAIT(_dbCon->getDeviceKeys()); keys.has_value())
    TC_RETURN(*keys);
  auto ret = DeviceKeys::create();
  TC_AWAIT(_dbCon->setDeviceKeys(ret));
  TC_RETURN(ret);
}

tc::cotask<std::optional<Crypto::PublicSignatureKey>>
LocalUserStore::findTrustchainPublicSignatureKey() const
{
  TC_RETURN(TC_AWAIT(_dbCon->findTrustchainPublicSignatureKey()));
}

tc::cotask<void> LocalUserStore::setTrustchainPublicSignatureKey(
    Crypto::PublicSignatureKey const& sigKey)
{
  TC_AWAIT(_dbCon->setTrustchainPublicSignatureKey(sigKey));
}

tc::cotask<std::optional<LocalUser>> LocalUserStore::findLocalUser(
    Trustchain::UserId const& userId) const
{
  auto const keys = TC_AWAIT(getDeviceKeys());
  auto const deviceId = TC_AWAIT(_dbCon->getDeviceId());
  if (!deviceId)
    TC_RETURN(std::nullopt);
  auto const userKeys = TC_AWAIT(_dbCon->getUserKeyPairs());
  TC_RETURN(std::make_optional(LocalUser(userId, *deviceId, keys, userKeys)));
}
}