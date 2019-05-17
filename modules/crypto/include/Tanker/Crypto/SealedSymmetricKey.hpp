#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Sealed.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<Sealed<SymmetricKey>,
                                             Sealed<SymmetricKey>::arraySize>;

using SealedSymmetricKey = Sealed<SymmetricKey>;
}
}
