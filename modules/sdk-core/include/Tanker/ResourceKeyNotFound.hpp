#pragma once

#include <string>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Error
{
class ResourceKeyNotFound : public Exception
{
public:
  ResourceKeyNotFound(Trustchain::ResourceId const& resourceId)
    : Exception(Code::ResourceKeyNotFound,
                fmt::format("couldn't find key for {:s}", resourceId)),
      _resourceId(resourceId)
  {
  }

  Trustchain::ResourceId const& resourceId()
  {
    return _resourceId;
  }

private:
  Trustchain::ResourceId const _resourceId;
};
}
}
