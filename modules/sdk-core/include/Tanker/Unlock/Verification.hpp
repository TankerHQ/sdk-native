#pragma once

#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>

#include <mpark/variant.hpp>

namespace Tanker
{
namespace Unlock
{
struct EmailVerification
{
  Email email;
  VerificationCode verificationCode;
};

using Verification =
    mpark::variant<VerificationKey, EmailVerification, Password>;
using VerificationMethod = mpark::variant<VerificationKey, Email, Password>;
}
}
