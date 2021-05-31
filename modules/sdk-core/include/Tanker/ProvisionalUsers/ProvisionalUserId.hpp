#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>

namespace Tanker::ProvisionalUsers
{
struct ProvisionalUserId
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
};

bool operator<(ProvisionalUserId const& l, ProvisionalUserId const& r);
}
