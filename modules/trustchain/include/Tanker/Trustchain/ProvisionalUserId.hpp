#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

namespace Tanker::Trustchain
{
#define TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_USER_ID_ATTRIBUTES \
  (appSignaturePublicKey, Crypto::PublicSignatureKey),           \
      (tankerSignaturePublicKey, Crypto::PublicSignatureKey)

class ProvisionalUserId
{
  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      ProvisionalUserId,
      TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_USER_ID_ATTRIBUTES)

  friend void from_serialized(Serialization::SerializedSource& ss,
                              ProvisionalUserId& k);
};

bool operator<(ProvisionalUserId const& l, ProvisionalUserId const& r);

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(ProvisionalUserId)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(ProvisionalUserId)
}
