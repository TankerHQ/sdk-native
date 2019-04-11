#pragma once

#include <string>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/UserId.hpp>

namespace Tanker
{
namespace Error
{

class ResourceKeyNotFound : public Exception
{
public:
  ResourceKeyNotFound(Crypto::Mac const& resourceId)
    : Exception(Code::ResourceKeyNotFound,
                fmt::format("couldn't find key for {:s}", resourceId)),
      _resourceId(resourceId)
  {
  }

  Crypto::Mac const& resourceId()
  {
    return _resourceId;
  }

private:
  Crypto::Mac const _resourceId;
};
}
}

