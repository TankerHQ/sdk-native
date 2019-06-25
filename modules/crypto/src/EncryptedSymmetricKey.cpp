#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>

#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <algorithm>

namespace Tanker
{
namespace Crypto
{
void from_serialized(Serialization::SerializedSource& ss,
                     EncryptedSymmetricKey& esk)
{
  auto const keySize = ss.read_varint();
  if (keySize != EncryptedSymmetricKey::arraySize)
  {
    throw Errors::Exception(Errc::InvalidBufferSize,
                            "invalid encrypted symmetric key size");
  }
  auto sp = ss.read(EncryptedSymmetricKey::arraySize);
  std::copy(sp.begin(), sp.end(), esk.begin());
}

std::uint8_t* to_serialized(std::uint8_t* it, EncryptedSymmetricKey const& esk)
{
  it = Serialization::varint_write(it, EncryptedSymmetricKey::arraySize);
  return std::copy(esk.begin(), esk.end(), it);
}
}
}
