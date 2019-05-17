#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Sealed.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<
    Sealed<SealedSymmetricKey>,
    Sealed<SealedSymmetricKey>::arraySize>;

using TwoTimesSealedSymmetricKey = Sealed<SealedSymmetricKey>;
}
}
