#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>

namespace Tanker::ProvisionalUsers
{
struct PublicUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicEncryptionKey appEncryptionPublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::PublicEncryptionKey tankerEncryptionPublicKey;
};

bool operator<(PublicUser const& l, PublicUser const& r);
}
