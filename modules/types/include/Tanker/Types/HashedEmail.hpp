#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
using HashedEmail = Crypto::BasicHash<struct HashedEmailImpl>;
}
