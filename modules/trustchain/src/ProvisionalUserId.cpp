#include <Tanker/Trustchain/ProvisionalUserId.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::Trustchain
{
bool operator<(ProvisionalUserId const& l, ProvisionalUserId const& r)
{
  return std::tie(l.appSignaturePublicKey(), l.tankerSignaturePublicKey()) <
         std::tie(r.appSignaturePublicKey(), r.tankerSignaturePublicKey());
}

bool operator>(ProvisionalUserId const& l, ProvisionalUserId const& r)
{
  return std::tie(l.appSignaturePublicKey(), l.tankerSignaturePublicKey()) >
         std::tie(r.appSignaturePublicKey(), r.tankerSignaturePublicKey());
}

bool operator>=(ProvisionalUserId const& l, ProvisionalUserId const& r)
{
  return std::tie(l.appSignaturePublicKey(), l.tankerSignaturePublicKey()) >=
         std::tie(r.appSignaturePublicKey(), r.tankerSignaturePublicKey());
}

bool operator<=(ProvisionalUserId const& l, ProvisionalUserId const& r)
{
  return std::tie(l.appSignaturePublicKey(), l.tankerSignaturePublicKey()) <=
         std::tie(r.appSignaturePublicKey(), r.tankerSignaturePublicKey());
}

TANKER_TRUSTCHAIN_DATA_DEFINE_SERIALIZATION(
    ProvisionalUserId, TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_USER_ID_ATTRIBUTES)
TANKER_TRUSTCHAIN_DATA_DEFINE_TO_JSON(
    ProvisionalUserId, TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_USER_ID_ATTRIBUTES)
}
