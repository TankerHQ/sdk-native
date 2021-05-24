#include <Tanker/ProvisionalUsers/PublicUser.hpp>

namespace Tanker::ProvisionalUsers
{
bool operator<(PublicUser const& l, PublicUser const& r)
{
  return std::tie(l.appSignaturePublicKey, l.tankerSignaturePublicKey) <
         std::tie(r.appSignaturePublicKey, r.tankerSignaturePublicKey);
}
}
