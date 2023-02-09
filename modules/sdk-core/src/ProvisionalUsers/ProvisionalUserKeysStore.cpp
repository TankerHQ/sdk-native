#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

TLOG_CATEGORY(ProvisionalUserKeysStore);

namespace Tanker
{
namespace
{
// Prefix should never be reused. List of previously used prefix:
// None
std::string const KeyPrefix = "provisionaluserkeys-";
std::string const IndexPrefix = "provisionaluserkeys-index-";

std::vector<uint8_t> serializeStoreKey(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey)
{
  std::vector<uint8_t> keyBuffer(KeyPrefix.size() +
                                 appPublicSignatureKey.size() +
                                 tankerPublicSignatureKey.size());
  auto it = keyBuffer.data();
  it = std::copy(KeyPrefix.begin(), KeyPrefix.end(), it);
  it = Serialization::serialize(it, appPublicSignatureKey);
  it = Serialization::serialize(it, tankerPublicSignatureKey);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}

std::vector<uint8_t> serializeStoreValue(
    ProvisionalUserKeys const& provisionalUserKeys)
{
  std::vector<uint8_t> valueBuffer(
      provisionalUserKeys.appKeys.publicKey.size() +
      provisionalUserKeys.appKeys.privateKey.size() +
      provisionalUserKeys.tankerKeys.publicKey.size() +
      provisionalUserKeys.tankerKeys.privateKey.size());
  auto it = valueBuffer.data();
  it = Serialization::serialize(it, provisionalUserKeys.appKeys.publicKey);
  it = Serialization::serialize(it, provisionalUserKeys.appKeys.privateKey);
  it = Serialization::serialize(it, provisionalUserKeys.tankerKeys.publicKey);
  it = Serialization::serialize(it, provisionalUserKeys.tankerKeys.privateKey);
  assert(it == valueBuffer.data() + valueBuffer.size());
  return valueBuffer;
}

ProvisionalUserKeys deserializeStoreValue(gsl::span<uint8_t const> serialized)
{
  ProvisionalUserKeys provisionalUserKeys;
  auto it = Serialization::SerializedSource{serialized};
  Serialization::deserialize_to(it, provisionalUserKeys.appKeys.publicKey);
  Serialization::deserialize_to(it, provisionalUserKeys.appKeys.privateKey);
  Serialization::deserialize_to(it, provisionalUserKeys.tankerKeys.publicKey);
  Serialization::deserialize_to(it, provisionalUserKeys.tankerKeys.privateKey);

  if (!it.eof())
    throw Errors::formatEx(
        Errors::Errc::InternalError,
        "failed to deserialize provisional user keys, the cache is corrupt");

  return provisionalUserKeys;
}

std::vector<uint8_t> serializeIndexKey(
    Crypto::PublicSignatureKey const& appPublicSignatureKey)
{
  std::vector<uint8_t> keyBuffer(IndexPrefix.size() +
                                 appPublicSignatureKey.size());
  auto it = keyBuffer.data();
  it = std::copy(IndexPrefix.begin(), IndexPrefix.end(), it);
  it = Serialization::serialize(it, appPublicSignatureKey);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}

std::vector<uint8_t> serializeIndexValue(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey)
{
  return serializeStoreKey(appPublicSignatureKey, tankerPublicSignatureKey);
}
}

ProvisionalUserKeysStore::ProvisionalUserKeysStore(
    Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db)
  : _userSecret(userSecret), _db(db)
{
}

tc::cotask<void> ProvisionalUserKeysStore::putProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey,
    ProvisionalUserKeys const& provisionalUserKeys)
{
  FUNC_TIMER(DB);
  TDEBUG("Adding provisional user keys for {} {}",
        appPublicSigKey,
        tankerPublicSigKey);

  auto const keyBuffer = serializeStoreKey(appPublicSigKey, tankerPublicSigKey);
  auto const valueBuffer = serializeStoreValue(provisionalUserKeys);

  auto const indexKeyBuffer = serializeIndexKey(appPublicSigKey);
  auto const indexValueBuffer =
      serializeIndexValue(appPublicSigKey, tankerPublicSigKey);

  auto const encryptedValue = DataStore::encryptValue(_userSecret, valueBuffer);

  std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>>
      keyValues{{keyBuffer, encryptedValue},
                {indexKeyBuffer, indexValueBuffer}};

  _db->putCacheValues(keyValues, DataStore::OnConflict::Ignore);
  TC_RETURN();
}

tc::cotask<std::optional<ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const keyBuffer =
        serializeStoreKey(appPublicSigKey, tankerPublicSigKey);
    auto const keys = {gsl::make_span(keyBuffer)};
    auto const result = _db->findCacheValues(keys);
    if (!result.at(0))
      TC_RETURN(std::nullopt);

    auto const decryptedValue =
        TC_AWAIT(DataStore::decryptValue(_userSecret, *result.at(0)));

    TC_RETURN(deserializeStoreValue(decryptedValue));
  }
  catch (Errors::Exception const& e)
  {
    DataStore::handleError(e);
  }
}

tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
ProvisionalUserKeysStore::findProvisionalUserKeysByAppPublicSignatureKey(
    Crypto::PublicSignatureKey const& appPublicSignatureKey) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const indexKey = serializeIndexKey(appPublicSignatureKey);
    auto const indexKeys = {gsl::make_span(indexKey)};
    auto const indexResult = _db->findCacheValues(indexKeys);
    if (!indexResult.at(0))
      TC_RETURN(std::nullopt);

    auto const keys = {gsl::make_span(*indexResult.at(0))};
    auto const result = _db->findCacheValues(keys);
    if (!result.at(0))
      // There's an index but no entry, weird...
      TC_RETURN(std::nullopt);

    auto const decryptedValue =
        TC_AWAIT(DataStore::decryptValue(_userSecret, *result.at(0)));

    TC_RETURN(deserializeStoreValue(decryptedValue));
  }
  catch (Errors::Exception const& e)
  {
    DataStore::handleError(e);
  }
}
}
