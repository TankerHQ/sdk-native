#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

TLOG_CATEGORY(GroupStore);

using Tanker::Trustchain::GroupId;

namespace Tanker::Groups
{
namespace
{
std::string const KeyPrefix = "groups-";
std::string const IndexPrefix = "groups-index-encryptionpublickey-";

constexpr uint8_t TypeInternalGroup = 1;
constexpr uint8_t TypeExternalGroup = 2;

std::vector<uint8_t> serializeStoreKey(Trustchain::GroupId const& groupId)
{
  std::vector<uint8_t> keyBuffer(KeyPrefix.size() + groupId.size());
  auto it = keyBuffer.data();
  it = std::copy(KeyPrefix.begin(), KeyPrefix.end(), it);
  it = Serialization::serialize(it, groupId);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}

std::vector<uint8_t> serializeStoreValue(InternalGroup const& group)
{
  std::vector<uint8_t> valueBuffer(
      sizeof(uint8_t) + group.id.size() +
      Serialization::serialized_size(group.signatureKeyPair) +
      Serialization::serialized_size(group.encryptionKeyPair) +
      group.lastBlockHash.size() + group.lastKeyRotationBlockHash.size());
  auto it = valueBuffer.data();
  it = Serialization::serialize<uint8_t>(it, TypeInternalGroup);
  it = Serialization::serialize(it, group.id);
  it = Serialization::serialize(it, group.signatureKeyPair);
  it = Serialization::serialize(it, group.encryptionKeyPair);
  it = Serialization::serialize(it, group.lastBlockHash);
  it = Serialization::serialize(it, group.lastKeyRotationBlockHash);
  assert(it == valueBuffer.data() + valueBuffer.size());
  return valueBuffer;
}

std::vector<uint8_t> serializeStoreValue(ExternalGroup const& group)
{
  std::vector<uint8_t> valueBuffer(
      sizeof(uint8_t) + group.id.size() + group.publicSignatureKey.size() +
      group.encryptedPrivateSignatureKey.size() +
      group.publicEncryptionKey.size() + group.lastBlockHash.size() +
      group.lastKeyRotationBlockHash.size());
  auto it = valueBuffer.data();
  it = Serialization::serialize<uint8_t>(it, TypeExternalGroup);
  it = Serialization::serialize(it, group.id);
  it = Serialization::serialize(it, group.publicSignatureKey);
  it = Serialization::serialize(it, group.encryptedPrivateSignatureKey);
  it = Serialization::serialize(it, group.publicEncryptionKey);
  it = Serialization::serialize(it, group.lastBlockHash);
  it = Serialization::serialize(it, group.lastKeyRotationBlockHash);
  assert(it == valueBuffer.data() + valueBuffer.size());
  return valueBuffer;
}

std::vector<uint8_t> serializeStoreValue(Group const& group)
{
  return boost::variant2::visit(
      [](auto const& group) { return serializeStoreValue(group); }, group);
}

InternalGroup deserializeInternalGroup(Serialization::SerializedSource& ss)
{
  InternalGroup group{};
  Serialization::deserialize_to(ss, group.id);
  Serialization::deserialize_to(ss, group.signatureKeyPair);
  Serialization::deserialize_to(ss, group.encryptionKeyPair);
  Serialization::deserialize_to(ss, group.lastBlockHash);
  Serialization::deserialize_to(ss, group.lastKeyRotationBlockHash);
  return group;
}

ExternalGroup deserializeExternalGroup(Serialization::SerializedSource& ss)
{
  ExternalGroup group{};
  Serialization::deserialize_to(ss, group.id);
  Serialization::deserialize_to(ss, group.publicSignatureKey);
  Serialization::deserialize_to(ss, group.encryptedPrivateSignatureKey);
  Serialization::deserialize_to(ss, group.publicEncryptionKey);
  Serialization::deserialize_to(ss, group.lastBlockHash);
  Serialization::deserialize_to(ss, group.lastKeyRotationBlockHash);
  return group;
}

Group deserializeStoreValue(gsl::span<uint8_t const> serialized)
{
  auto ss = Serialization::SerializedSource{serialized};

  Group group;
  uint8_t type = Serialization::deserialize<uint8_t>(ss);

  switch (type)
  {
  case TypeInternalGroup:
    group = deserializeInternalGroup(ss);
    break;
  case TypeExternalGroup:
    group = deserializeExternalGroup(ss);
    break;
  default:
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "failed to deserialize group, unknown type: {}",
                           int(type));
  }

  if (!ss.eof())
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "failed to deserialize group, the cache is corrupt");

  return group;
}

std::vector<uint8_t> serializeIndexKey(
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey)
{
  std::vector<uint8_t> keyBuffer(IndexPrefix.size() +
                                 groupPublicEncryptionKey.size());
  auto it = keyBuffer.data();
  it = std::copy(IndexPrefix.begin(), IndexPrefix.end(), it);
  it = Serialization::serialize(it, groupPublicEncryptionKey);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}

std::vector<uint8_t> serializeIndexValue(Trustchain::GroupId const& groupId)
{
  return serializeStoreKey(groupId);
}
}

Store::Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db)
  : _userSecret(userSecret), _db(db)
{
}

tc::cotask<void> Store::put(Group const& group)
{
  FUNC_TIMER(DB);
  auto const groupId = getGroupId(group);
  TDEBUG("Adding group {}", groupId);

  auto const keyBuffer = serializeStoreKey(groupId);
  auto const valueBuffer = serializeStoreValue(group);

  auto const indexKeyBuffer = serializeIndexKey(getPublicEncryptionKey(group));
  auto const indexValueBuffer = serializeIndexValue(groupId);

  auto const encryptedValue = DataStore::encryptValue(_userSecret, valueBuffer);

  std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>>
      keyValues{{keyBuffer, encryptedValue},
                {indexKeyBuffer, indexValueBuffer}};

  _db->putCacheValues(keyValues, DataStore::OnConflict::Replace);
  TC_RETURN();
}

tc::cotask<std::optional<Group>> Store::findById(GroupId const& groupId) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const keyBuffer = serializeStoreKey(groupId);
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

tc::cotask<std::optional<InternalGroup>>
Store::findInternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  auto optGroup = TC_AWAIT(findByPublicEncryptionKey(publicEncryptionKey));
  if (!optGroup ||
      !boost::variant2::holds_alternative<InternalGroup>(*optGroup))
    TC_RETURN(std::nullopt);
  TC_RETURN(boost::variant2::get<InternalGroup>(*optGroup));
}

tc::cotask<std::optional<Group>> Store::findByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const indexKey = serializeIndexKey(publicEncryptionKey);
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
