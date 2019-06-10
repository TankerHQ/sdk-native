#include <Tanker/UserKeyStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>

#include <fmt/format.h>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(UserKeyStore);

namespace Tanker
{
UserKeyStore::UserKeyStore(DataStore::ADatabase* dbConn) : _db(dbConn)
{
}

tc::cotask<void> UserKeyStore::putPrivateKey(
    Crypto::PublicEncryptionKey const& publicKey,
    Crypto::PrivateEncryptionKey const& privateKey)
{
  TINFO("Adding user key for {}", publicKey);
  TC_AWAIT(_db->putUserPrivateKey(publicKey, privateKey));
}

tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
UserKeyStore::findKeyPair(Crypto::PublicEncryptionKey const& publicKey) const
{
  try
  {
    TC_RETURN(TC_AWAIT(_db->getUserKeyPair(publicKey)));
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == DataStore::Errc::RecordNotFound)
      TC_RETURN(nonstd::nullopt);
    throw;
  }
}

tc::cotask<Crypto::EncryptionKeyPair> UserKeyStore::getKeyPair(
    Crypto::PublicEncryptionKey const& publicKey) const
{
  auto const optKeyPair = TC_AWAIT(findKeyPair(publicKey));
  if (!optKeyPair)
  {
    throw Errors::formatEx(Errors::Errc::NotFound,
                           "cannot find user key for public key: {}",
                           publicKey);
  }
  TC_RETURN(*optKeyPair);
}

tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
UserKeyStore::getOptLastKeyPair() const
{
  TC_RETURN(TC_AWAIT(_db->getUserOptLastKeyPair()));
}

tc::cotask<Crypto::EncryptionKeyPair> UserKeyStore::getLastKeyPair() const
{
  auto const keyPair = TC_AWAIT(getOptLastKeyPair());
  if (!keyPair)
  {
    throw Errors::formatEx(Errors::Errc::NotFound,
                           "user does not have a user key yet");
  }
  TC_RETURN(*keyPair);
}

tc::cotask<bool> UserKeyStore::isEmpty() const
{
  auto const keyPair = TC_AWAIT(getOptLastKeyPair());
  TC_RETURN(keyPair.has_value());
}
}
