#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedPrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

#include <vector>

namespace Tanker
{
#define TANKER_GROUP_PROVISIONAL_USER_ATTRIBUTES              \
  (appPublicSignatureKey, Crypto::PublicSignatureKey),        \
      (tankerPublicSignatureKey, Crypto::PublicSignatureKey), \
      (encryptedPrivateEncryptionKey,                         \
       Crypto::TwoTimesSealedPrivateEncryptionKey)

class GroupProvisionalUser
{
  TANKER_TRUSTCHAIN_ACTION_IMPLEMENTATION(
      GroupProvisionalUser, TANKER_GROUP_PROVISIONAL_USER_ATTRIBUTES)
};
}
