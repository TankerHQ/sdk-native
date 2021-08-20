#pragma once

#include <Tanker/Status.hpp>
#include <Tanker/Verification/Verification.hpp>

#include <optional>

namespace Tanker
{
struct AttachResult
{
  Tanker::Status status;
  std::optional<Verification::VerificationMethod> verificationMethod;
};

bool operator==(AttachResult const& l, AttachResult const& r);
bool operator!=(AttachResult const& l, AttachResult const& r);
}
