#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Users/LocalUser.hpp>

TLOG_CATEGORY(LocalUserStore);

namespace Tanker::Users
{

LocalUserStore::LocalUserStore(DataStore::Database* db) : _dbCon(db)
{
}

tc::cotask<bool> LocalUserStore::isInitialized()
{
  TC_RETURN(TC_AWAIT(_dbCon->isDeviceInitialized()));
}

tc::cotask<void> LocalUserStore::setDeviceId(
    Trustchain::DeviceId const& deviceId)
{
  TC_AWAIT(_dbCon->setDeviceId(deviceId));
}

tc::cotask<void> LocalUserStore::putLocalUser(LocalUser const& user)
{
  TC_AWAIT(putUserKeys(user.userKeys()));
  TC_AWAIT(_dbCon->setDeviceInitialized());
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
  auto const initialized = TC_AWAIT(_dbCon->isDeviceInitialized());
  if (!initialized)
    TC_RETURN(std::nullopt);
  auto const deviceId = TC_AWAIT(_dbCon->getDeviceId());
  auto const userKeys = TC_AWAIT(_dbCon->getUserKeyPairs());
  TC_RETURN(std::make_optional(LocalUser(userId, *deviceId, keys, userKeys)));
}
}
