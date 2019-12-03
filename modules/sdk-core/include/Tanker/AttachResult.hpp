#pragma once

#include <Tanker/Status.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <optional>

namespace Tanker
{
struct AttachResult
{
  Tanker::Status status;
  std::optional<Unlock::VerificationMethod> verificationMethod;
};

bool operator==(AttachResult const& l, AttachResult const& r);
bool operator!=(AttachResult const& l, AttachResult const& r);
}
