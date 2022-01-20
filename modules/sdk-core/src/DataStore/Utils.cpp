#include <Tanker/DataStore/Utils.hpp>

#include <Tanker/Crypto/Errors/ErrcCategory.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Errors/ErrcCategory.hpp>

TLOG_CATEGORY(DataStore);

namespace Tanker::DataStore
{
[[noreturn]] void handleError(Errors::Exception const& e)
{
  if (e.errorCode().category() == Serialization::ErrcCategory() ||
      e.errorCode().category() == Crypto::ErrcCategory() ||
      e.errorCode() == Errors::Errc::InvalidArgument)
  {
    TERROR("Failed to decrypt/deserialize database buffer: {}", e.what());
    throw Errors::Exception(
        DataStore::Errc::DatabaseCorrupt,
        "database is corrupted, or an incorrect identity was used");
  }
  else
    throw;
}

// We chose the V2 format for storage encryption.
// V1 is deprecated
// V3 has a fixed nonce, so it's not meant to be used multiple times with the
// same key
// V4 is for streams
// V5 has a resource ID which we don't need
// See https://github.com/TankerHQ/spec/blob/master/encryption_formats.md

std::vector<uint8_t> encryptValue(Crypto::SymmetricKey const& userSecret,
                                  gsl::span<uint8_t const> value)
{
  std::vector<uint8_t> encryptedValue(EncryptorV2::encryptedSize(value.size()));
  EncryptorV2::encryptSync(encryptedValue.data(), value, userSecret);
  return encryptedValue;
}

tc::cotask<std::vector<uint8_t>> decryptValue(
    Crypto::SymmetricKey const& userSecret,
    gsl::span<uint8_t const> encryptedValue)
{
  std::vector<uint8_t> decryptedValue(
      EncryptorV2::decryptedSize(encryptedValue));
  TC_AWAIT(EncryptorV2::decrypt(decryptedValue, userSecret, encryptedValue));
  TC_RETURN(decryptedValue);
}
}
