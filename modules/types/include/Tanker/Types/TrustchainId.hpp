#pragma once

#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/Types.hpp>

namespace Tanker
{
using TrustchainId = Crypto::BasicHash<struct TrustchainIdImpl>;
}
