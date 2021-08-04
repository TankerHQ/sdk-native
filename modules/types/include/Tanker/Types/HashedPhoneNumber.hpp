#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
using HashedPhoneNumber = Crypto::BasicHash<struct HashedPhoneNumberImpl>;
}
