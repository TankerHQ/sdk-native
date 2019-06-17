#pragma once

#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Types/VerificationCode.hpp>

#include <mpark/variant.hpp>

namespace Tanker
{
namespace Unlock
{
using DeviceLocker = mpark::variant<Passphrase, VerificationCode, VerificationKey>;
}
}
