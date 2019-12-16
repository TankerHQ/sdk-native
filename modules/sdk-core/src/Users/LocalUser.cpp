#include <Tanker/Users/LocalUser.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>

#include <fmt/format.h>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(LocalUser);

namespace Tanker::Users
{
tc::cotask<LocalUser::Ptr> LocalUser::open(
    Identity::SecretPermanentIdentity const& identity,
    DataStore::ADatabase* dbCon)
{
  auto const deviceKeys = [&] {
    auto const keys = TC_AWAIT(dbCon->getDeviceKeys());
    if (keys)
      return keys.value();
    auto ret = DeviceKeys::create();
    TC_AWAIT(dbCon->setDeviceKeys(ret));
    return ret;
  }();
  auto const deviceId =
      TC_AWAIT(dbCon->getDeviceId()).value_or(Trustchain::DeviceId{});
  auto const trustchainPublicSignatureKey =
      TC_AWAIT(dbCon->findTrustchainPublicSignatureKey())
          .value_or(Crypto::PublicSignatureKey{});
  TC_RETURN(std::make_unique<LocalUser>(identity.delegation.userId,
                                        deviceId,
                                        identity.userSecret,
                                        deviceKeys,
                                        trustchainPublicSignatureKey,
                                        dbCon));
}

LocalUser::LocalUser(
    Trustchain::UserId const& userId,
    Trustchain::DeviceId const& deviceId,
    Crypto::SymmetricKey const& userSecret,
    DeviceKeys const& deviceKeys,
    Crypto::PublicSignatureKey const& trustchainPublicSignatureKey,
    DataStore::ADatabase* dbCon)
  : _userId(userId),
    _deviceId(deviceId),
    _userSecret(userSecret),
    _deviceKeys(deviceKeys),
    _trustchainPublicSignatureKey(trustchainPublicSignatureKey),
    _db(dbCon)
{
}

Trustchain::DeviceId const& LocalUser::deviceId() const
{
  return _deviceId;
}

tc::cotask<void> LocalUser::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  if (!_deviceId.is_null() && deviceId != _deviceId)
    throw Errors::AssertionError("deviceId already set");
  TC_AWAIT(_db->setDeviceId(deviceId));
  _deviceId = deviceId;
}

tc::cotask<void> LocalUser::setTrustchainPublicSignatureKey(
    Crypto::PublicSignatureKey const& key)
{
  if (!_trustchainPublicSignatureKey.is_null() &&
      key != _trustchainPublicSignatureKey)
    throw Errors::AssertionError("trustchainPublicSignatureKey is already set");
  TC_AWAIT(_db->setTrustchainPublicSignatureKey(key));
  _trustchainPublicSignatureKey = key;
}

Crypto::PublicSignatureKey const& LocalUser::trustchainPublicSignatureKey()
    const
{
  return _trustchainPublicSignatureKey;
}

DeviceKeys const& LocalUser::deviceKeys() const
{
  return _deviceKeys;
}

Trustchain::UserId const& LocalUser::userId() const
{
  return _userId;
}

Crypto::SymmetricKey const& LocalUser::userSecret() const
{
  return _userSecret;
}

tc::cotask<void> LocalUser::insertUserKey(
    Crypto::EncryptionKeyPair const& keyPair)
{
  TINFO("Adding user key for {}", keyPair.publicKey);
  TC_AWAIT(_db->putUserPrivateKey(keyPair.publicKey, keyPair.privateKey));
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>> LocalUser::findKeyPair(
    Crypto::PublicEncryptionKey const& publicKey) const try
{
  TC_RETURN(TC_AWAIT(_db->getUserKeyPair(publicKey)));
}
catch (Errors::Exception const& e)
{
  if (e.errorCode() == DataStore::Errc::RecordNotFound)
    TC_RETURN(std::nullopt);
  throw;
}

tc::cotask<Crypto::EncryptionKeyPair> LocalUser::currentKeyPair() const
{
  auto const keyPair = TC_AWAIT(_db->getUserOptLastKeyPair());
  if (!keyPair)
    throw Errors::Exception(make_error_code(Errors::Errc::InternalError),
                            "user does not have a user key yet");
  TC_RETURN(*keyPair);
}
}
