#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>

#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>

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

class VerificationMethod
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION_ZERO(
      VerificationMethod, (VerificationKey, Email, Password))

private:
  friend void from_json(nlohmann::json const&, VerificationMethod&);
  friend bool operator<(VerificationMethod const& a,
                        VerificationMethod const& b);
};

void to_json(nlohmann::json&, VerificationMethod const&);
void from_json(nlohmann::json const&, VerificationMethod&);

inline bool operator<(VerificationMethod const& a, VerificationMethod const& b)
{
  return a._variant < b._variant;
}
}
}

