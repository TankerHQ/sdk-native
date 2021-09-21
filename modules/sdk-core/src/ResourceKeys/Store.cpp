#include <Tanker/ResourceKeys/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <sqlpp11/sqlite3/insert_or.h>

TLOG_CATEGORY(ResourceKeys::Store);

using Tanker::Trustchain::ResourceId;
using ResourceKeysTable = Tanker::DbModels::resource_keys::resource_keys;

namespace Tanker::ResourceKeys
{
namespace
{
std::string const KeyPrefix = "resourcekey-";

std::vector<uint8_t> serializeStoreKey(ResourceId const& resourceId)
{
  std::vector<uint8_t> keyBuffer(KeyPrefix.size() + resourceId.size());
  auto it = keyBuffer.data();
  it = std::copy(KeyPrefix.begin(), KeyPrefix.end(), it);
  it = Serialization::serialize(it, resourceId);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}
}

Store::Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db)
  : _userSecret(userSecret), _db(db)
{
}

tc::cotask<void> Store::putKey(ResourceId const& resourceId,
                               Crypto::SymmetricKey const& key)
{
  TINFO("Adding key for {}", resourceId);
  FUNC_TIMER(DB);

  auto const storeRid = serializeStoreKey(resourceId);

  std::vector<uint8_t> encryptedKey(EncryptorV2::encryptedSize(key.size()));
  EncryptorV2::encryptSync(encryptedKey.data(), key, _userSecret);

  std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>>
      keyValues{{storeRid, encryptedKey}};

  _db->putCacheValues(keyValues, DataStore::OnConflict::Ignore);
  TC_RETURN();
}

tc::cotask<Crypto::SymmetricKey> Store::getKey(
    ResourceId const& resourceId) const
{
  auto const key = TC_AWAIT(findKey(resourceId));
  if (!key)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           FMT_STRING("key not found for resource {:s}"),
                           resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<std::optional<Crypto::SymmetricKey>> Store::findKey(
    ResourceId const& resourceId) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const storeRid = serializeStoreKey(resourceId);
    auto const keys = {gsl::make_span(storeRid)};
    auto const result = _db->findCacheValues(keys);
    if (!result.at(0))
      TC_RETURN(std::nullopt);

    auto const& encryptedKey = *result.at(0);
    std::vector<uint8_t> key(EncryptorV2::decryptedSize(encryptedKey));
    TC_AWAIT(EncryptorV2::decrypt(key.data(), _userSecret, encryptedKey));

    TC_RETURN(Crypto::SymmetricKey{key});
  }
  catch (Errors::Exception const& e)
  {
    DataStore::handleError(e);
  }
}
}
