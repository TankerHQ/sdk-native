#include <Tanker/TransparentSession/Store.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <gsl/gsl-lite.hpp>

using namespace std::literals;

namespace Tanker::TransparentSession
{
namespace
{
constexpr auto Version = 1;
// Prefix should never be reused. List of previously used prefix:
// None
std::string const KeyPrefix = "transparent-session-";

std::vector<uint8_t> serializeStoreKey(Crypto::Hash const& recipients)
{
  std::vector<uint8_t> keyBuffer(KeyPrefix.size() + recipients.size());
  auto it = keyBuffer.data();
  it = std::copy(KeyPrefix.begin(), KeyPrefix.end(), it);
  it = Serialization::serialize(it, recipients);
  assert(it == keyBuffer.data() + keyBuffer.size());
  return keyBuffer;
}

std::vector<uint8_t> serializeTransparentSession(TransparentSessionData const& sessionData)
{
  std::vector<uint8_t> data(sizeof(uint8_t) + Serialization::serialized_size(sessionData.creationTimestamp) +
                            Serialization::serialized_size(sessionData.sessionId) +
                            Serialization::serialized_size(sessionData.sessionKey));

  auto it = data.data();
  it = Serialization::serialize<uint8_t>(it, Version);
  it = Serialization::serialize(it, sessionData.creationTimestamp);
  it = Serialization::serialize(it, sessionData.sessionId);
  it = Serialization::serialize(it, sessionData.sessionKey);
  return data;
}

TransparentSessionData deserializeTransparentSession(gsl::span<const uint8_t> payload)
{
  TransparentSessionData out;
  Serialization::SerializedSource source(payload);

  uint8_t version;
  Serialization::deserialize_to(source, version);

  if (version != Version)
    throw Errors::formatEx(DataStore::Errc::InvalidDatabaseVersion,
                           "unsupported transparent session storage version: {}",
                           static_cast<int>(version));

  Serialization::deserialize_to(source, out.creationTimestamp);
  Serialization::deserialize_to(source, out.sessionId);
  Serialization::deserialize_to(source, out.sessionKey);

  if (!source.eof())
  {
    throw Errors::formatEx(Serialization::Errc::TrailingInput, "{} trailing bytes", source.remaining_size());
  }

  return out;
}
}

Store::Store(Crypto::SymmetricKey const& userSecret, DataStore::DataStore* db) : _userSecret(userSecret), _db(db)
{
}

Crypto::Hash Store::hashRecipients(std::vector<SPublicIdentity> users, std::vector<SGroupId> groups)
{
  users |= Actions::deduplicate;
  groups |= Actions::deduplicate;

  std::vector<uint8_t> input;
  auto serializeWithLenPrefix = [&](auto const& s) {
    auto pos = input.size();
    input.resize(input.size() + sizeof(uint32_t) + s.size());
    Serialization::serialize<uint32_t>(&input[pos], s.size());
    std::copy(s.begin(), s.end(), &input[pos + sizeof(uint32_t)]);
  };

  for (auto&& user : users)
    serializeWithLenPrefix(user);
  input.push_back('|');
  for (auto&& group : groups)
    serializeWithLenPrefix(group);

  return Crypto::generichash(input);
}

tc::cotask<void> Store::put(Crypto::Hash const& recipientsHash,
                            Crypto::SimpleResourceId const& sessionId,
                            Crypto::SymmetricKey const& sessionKey,
                            std::uint64_t creationTimestamp)
{
  FUNC_TIMER(DB);
  auto const keyBuffer = serializeStoreKey(recipientsHash);
  TransparentSessionData sessionData{creationTimestamp, sessionId, sessionKey};
  auto const valueBuffer = serializeTransparentSession(sessionData);
  auto const encryptedValue = DataStore::encryptValue(_userSecret, valueBuffer);

  std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>> keyValues{{keyBuffer, encryptedValue}};
  _db->putCacheValues(keyValues, DataStore::OnConflict::Replace);
  TC_RETURN();
}

tc::cotask<std::optional<TransparentSessionData>> Store::get(Crypto::Hash const& recipientsHash) const
{
  FUNC_TIMER(DB);

  try
  {
    auto const keyBuffer = serializeStoreKey(recipientsHash);
    auto const keys = {gsl::make_span(keyBuffer)};
    auto const result = _db->findCacheValues(keys);
    if (!result.at(0))
      TC_RETURN(std::nullopt);

    auto const decryptedValue = TC_AWAIT(DataStore::decryptValue(_userSecret, *result.at(0)));
    TC_RETURN(deserializeTransparentSession(decryptedValue));
  }
  catch (Errors::Exception const& e)
  {
    DataStore::handleError(e);
  }
}

}
