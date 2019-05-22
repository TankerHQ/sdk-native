#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
enum class Errc
{
  AsymmetricDecryptionFailed = 1,
  AsymmetricEncryptionFailed,
  AeadDecryptionFailed,
  SealedEncryptionFailed,
  SealedDecryptionFailed,
  InvalidEncryptedDataSize,
  InvalidSealedDataSize,
  InvalidBufferSize,
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::Crypto::Errc> : std::true_type
{
};
}
