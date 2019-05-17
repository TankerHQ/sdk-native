#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Sealed.hpp>

namespace Tanker
{
namespace Crypto
{
extern template class BasicCryptographicType<
    Sealed<PrivateSignatureKey>,
    Sealed<PrivateSignatureKey>::arraySize>;

using SealedPrivateSignatureKey = Sealed<PrivateSignatureKey>;
}
}
