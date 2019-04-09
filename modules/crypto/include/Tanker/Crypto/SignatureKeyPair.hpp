#pragma once

#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/KeyPair.hpp>

namespace Tanker
{
namespace Crypto
{
using SignatureKeyPair = KeyPair<KeyUsage::Signature>;
}
}
