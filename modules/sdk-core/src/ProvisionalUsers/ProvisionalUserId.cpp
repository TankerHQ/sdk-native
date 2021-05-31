#include <Tanker/ProvisionalUsers/ProvisionalUserId.hpp>

namespace Tanker::ProvisionalUsers
{
bool operator<(ProvisionalUserId const& l, ProvisionalUserId const& r)
{
  return std::tie(l.appSignaturePublicKey, l.tankerSignaturePublicKey) <
         std::tie(r.appSignaturePublicKey, r.tankerSignaturePublicKey);
}
}
