#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
using DeviceId = Crypto::BasicHash<struct DeviceIdImpl>;
}
