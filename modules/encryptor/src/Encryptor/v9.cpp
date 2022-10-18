#include <Tanker/Encryptor/v9.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/ResourceId.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <stdexcept>

using namespace Tanker::Crypto;

namespace Tanker
{
namespace
{
constexpr auto versionSize = 1;
constexpr auto overheadSize = versionSize + SimpleResourceId::arraySize +
                              SubkeySeed::arraySize + Mac::arraySize;
constexpr auto macDataSize =
    versionSize + SimpleResourceId::arraySize + SubkeySeed::arraySize;

// version 9 format layout:
// [version, 1B] [session id, 16B] [seed/resource id, 16B] [ciphertext...]
// [mac, 16B]
void checkEncryptedFormat(gsl::span<std::uint8_t const> encryptedData)
{
  if (encryptedData.size() < overheadSize)
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "truncated encrypted buffer");
  }

  assert(encryptedData[0] == EncryptorV9::version());
}

SymmetricKey deriveSubkey(SymmetricKey const& sessionKey,
                          SubkeySeed const& subkeySeed)
{
  auto constexpr bufLen = SymmetricKey::arraySize + SubkeySeed::arraySize;
  std::array<std::uint8_t, bufLen> hashBuf;
  std::copy(sessionKey.begin(), sessionKey.end(), hashBuf.data());
  std::copy(subkeySeed.begin(),
            subkeySeed.end(),
            hashBuf.data() + SymmetricKey::arraySize);
  return generichash<SymmetricKey>(gsl::make_span(hashBuf));
}

std::array<uint8_t, macDataSize> makeMacData(SimpleResourceId const& sessionId,
                                             SubkeySeed const& subkeySeed)
{
  std::array<std::uint8_t, macDataSize> macData;
  macData[0] = EncryptorV9::version();
  std::copy(sessionId.begin(), sessionId.end(), macData.data() + versionSize);
  std::copy(subkeySeed.begin(),
            subkeySeed.end(),
            macData.data() + versionSize + SimpleResourceId::arraySize);
  return macData;
}
}

std::uint64_t EncryptorV9::encryptedSize(std::uint64_t clearSize)
{
  return clearSize + overheadSize;
}

std::uint64_t EncryptorV9::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  return encryptedData.size() - overheadSize;
}

tc::cotask<EncryptionMetadata> EncryptorV9::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<std::uint8_t const> clearData,
    SimpleResourceId const& sessionId,
    SymmetricKey const& sessionKey,
    SubkeySeed const& subkeySeed)
{
  // An IV is 24 bytes, so the first 16 will be session ID, last 8 will be zero
  auto iv = AeadIv{};
  std::copy(sessionId.begin(), sessionId.end(), iv.data());
  auto macData = makeMacData(sessionId, subkeySeed);
  auto key = deriveSubkey(sessionKey, subkeySeed);

  encryptedData[0] = version();
  std::copy(
      sessionId.begin(), sessionId.end(), encryptedData.data() + versionSize);
  std::copy(subkeySeed.begin(),
            subkeySeed.end(),
            encryptedData.data() + versionSize + SimpleResourceId::arraySize);
  auto const cipherText = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize + SubkeySeed::arraySize,
      clearData.size() + Mac::arraySize);
  encryptAead(key, iv, cipherText, clearData, macData);
  TC_RETURN((EncryptionMetadata{sessionId, sessionKey}));
}

tc::cotask<std::uint64_t> EncryptorV9::decrypt(
    gsl::span<std::uint8_t> decryptedData,
    Encryptor::ResourceKeyFinder const& keyFinder,
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  auto resourceId = extractResourceId(encryptedData);
  auto sessionId = resourceId.sessionId();
  auto subkeySeed = SubkeySeed{resourceId.individualResourceId()};

  std::optional key = TC_AWAIT(keyFinder(sessionId));
  if (key)
    key = deriveSubkey(*key, subkeySeed);
  else
    // If this returns nullopt too, tryDecryptAead will just throw for us
    key = TC_AWAIT(keyFinder(resourceId.individualResourceId()));

  // An IV is 24 bytes, so the first 16 will be session ID, last 8 will be zero
  auto iv = AeadIv{};
  std::copy(sessionId.begin(), sessionId.end(), iv.data());
  auto macData = makeMacData(sessionId, subkeySeed);

  uint64_t clearSize = decryptedSize(encryptedData);
  auto const data = encryptedData.subspan(
      versionSize + SimpleResourceId::arraySize + SubkeySeed::arraySize,
      clearSize + Mac::arraySize);
  tryDecryptAead(key, resourceId, iv, decryptedData, data, macData);
  TC_RETURN(clearSize);
}

CompositeResourceId EncryptorV9::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  checkEncryptedFormat(encryptedData);

  CompositeResourceId id;
  id[0] = CompositeResourceId::transparentSessionType();
  std::copy(encryptedData.begin() + versionSize,
            encryptedData.begin() + versionSize + SimpleResourceId::arraySize +
                SubkeySeed::arraySize,
            id.begin() + 1);
  return id;
}
}
