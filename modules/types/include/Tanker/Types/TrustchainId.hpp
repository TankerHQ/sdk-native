#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
using TrustchainId = Crypto::BasicHash<struct TrustchainIdImpl>;
}
