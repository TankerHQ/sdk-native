#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <mpark/variant.hpp>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>

#include <vector>

namespace Tanker
{
namespace Unlock
{
struct EncryptedEmailVerification
{
  Email email;
  std::vector<uint8_t> encrytpedEmail;
  VerificationCode verificationCode;
};

// Encrypted email and hashed passphrase
using VerificationRequest =
    mpark::variant<EncryptedEmailVerification, Crypto::Hash>;

nonstd::optional<VerificationRequest> makeVerificationRequest(
    Verification const& verification, Crypto::SymmetricKey const& userSecret);

void to_json(nlohmann::json& j, VerificationRequest const& c);
}
}
