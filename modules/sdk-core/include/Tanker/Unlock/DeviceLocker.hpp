#pragma once

#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Types/VerificationCode.hpp>

#include <mpark/variant.hpp>

namespace Tanker
{
namespace Unlock
{
using DeviceLocker = mpark::variant<Password, VerificationCode, VerificationKey>;
}
}
