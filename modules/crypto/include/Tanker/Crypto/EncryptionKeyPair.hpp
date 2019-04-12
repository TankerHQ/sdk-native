#pragma once

#include <Tanker/Crypto/KeyPair.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>

namespace Tanker
{
namespace Crypto
{
using EncryptionKeyPair = KeyPair<KeyUsage::Encryption>;
}
}
