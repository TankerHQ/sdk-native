#pragma once

#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedKeyPair.hpp>

namespace Tanker::Crypto
{
using SealedSignatureKeyPair = SealedKeyPair<KeyUsage::Signature>;
}