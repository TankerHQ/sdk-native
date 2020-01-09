
#pragma once

#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedKeyPair.hpp>

namespace Tanker::Crypto
{
using SealedEncryptionKeyPair = SealedKeyPair<KeyUsage::Encryption>;
}