#pragma once

#include <Tanker/Crypto/KeyPair.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

namespace Tanker
{
namespace Crypto
{
using SignatureKeyPair = KeyPair<KeyUsage::Signature>;
}
}
