#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker::Oidc
{
using Challenge = StringWrapper<struct ChallengeTag>;

using SignedChallenge = StringWrapper<struct SignedChallengeTag>;
}
