#include <Tanker/Crypto/Errors/ErrcCategory.hpp>

#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>

namespace Tanker
{
namespace Crypto
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::AsymmetricDecryptionFailed:
    return "asymmetric decryption failed";
  case Errc::AsymmetricEncryptionFailed:
    return "asymmetric encryption failed";
  case Errc::SealedDecryptionFailed:
    return "sealed decryption failed";
  case Errc::SealedEncryptionFailed:
    return "sealed encryption failed";
  case Errc::AeadDecryptionFailed:
    return "aead decryption failed";
  case Errc::InvalidEncryptedDataSize:
    return "invalid encrypted data size";
  case Errc::InvalidSealedDataSize:
    return "invalid sealed data size";
  case Errc::InvalidBufferSize:
    return "invalid buffer size";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
    case Errc::AsymmetricDecryptionFailed:
    case Errc::SealedDecryptionFailed:
    case Errc::AeadDecryptionFailed:
      return make_error_condition(Errors::Errc::DecryptionFailed);
    case Errc::AsymmetricEncryptionFailed:
    case Errc::SealedEncryptionFailed:
      return make_error_condition(Errors::Errc::InternalError);
    case Errc::InvalidEncryptedDataSize:
    case Errc::InvalidSealedDataSize:
    case Errc::InvalidBufferSize:
      return make_error_condition(Errors::Errc::InvalidArgument);
    default:
      return std::error_condition(c, *this);
  }
}
}
}
}
