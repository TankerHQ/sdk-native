#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Sealed.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<Sealed<SealedPrivateEncryptionKey>,
                                             Sealed<SealedPrivateEncryptionKey>::arraySize>;

using TwoTimesSealedPrivateEncryptionKey = Sealed<Sealed<PrivateEncryptionKey>>;
}
}
