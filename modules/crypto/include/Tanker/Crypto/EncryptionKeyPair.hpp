#pragma once

#include <Tanker/Crypto/KeyPair.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>

namespace Tanker
{
namespace Crypto
{
using EncryptionKeyPair = KeyPair<KeyUsage::Encryption>;
}
}
