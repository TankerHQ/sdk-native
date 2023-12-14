#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Sealed.hpp>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<Sealed<PrivateEncryptionKey>, Sealed<PrivateEncryptionKey>::arraySize>;

using SealedPrivateEncryptionKey = Sealed<PrivateEncryptionKey>;
}
}
