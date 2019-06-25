#include <Tanker/AttachResult.hpp>

namespace Tanker
{
bool operator==(AttachResult const& l, AttachResult const& r)
{
  return std::tie(l.status, l.verificationMethod) ==
         std::tie(r.status, r.verificationMethod);
}

bool operator!=(AttachResult const& l, AttachResult const& r)
{
  return !(l == r);
}
}
