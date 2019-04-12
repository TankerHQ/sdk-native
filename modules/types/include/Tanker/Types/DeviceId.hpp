#pragma once

#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/Types.hpp>

namespace Tanker
{
using DeviceId = Crypto::BasicHash<struct DeviceIdImpl>;
}
