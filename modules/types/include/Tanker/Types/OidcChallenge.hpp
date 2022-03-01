#pragma once

#include <Tanker/Types/StringWrapper.hpp>

namespace Tanker
{
using OidcChallenge = StringWrapper<struct OidcChallengeTag>;

using OidcSignedChallenge = StringWrapper<struct OidcSignedChallengeTag>;
}
