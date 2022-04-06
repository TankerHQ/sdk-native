#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker::Oidc
{
using Challenge = StringWrapper<struct ChallengeTag>;

using ChallengeSignature = StringWrapper<struct ChallengeSignatureTag>;

struct SignedChallenge
{
  Challenge challenge;
  ChallengeSignature signature;
};
}
