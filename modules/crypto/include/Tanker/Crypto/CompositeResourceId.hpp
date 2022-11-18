#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Mac.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>

#include <gsl/gsl-lite.hpp>

namespace Tanker::Crypto
{
namespace details
{
constexpr auto compositeTypeSize = 1;
constexpr auto compositeSize = compositeTypeSize + SimpleResourceId::arraySize +
                               SimpleResourceId::arraySize;
}

// Currently not a variant as there is still only a single composite resource
// ID type (type 0, used by transparent sessions)
// Format: Type (1 Byte) | Session ID (16 B) | Individual resource ID (16 B) |
class CompositeResourceId
  : public BasicCryptographicType<CompositeResourceId, details::compositeSize>
{
  using base_t::base_t;

public:
  static CompositeResourceId newTransparentSessionId(
      SimpleResourceId const& sessionId,
      SimpleResourceId const& individualResourceId)
  {
    CompositeResourceId id;
    id[0] = transparentSessionType();
    std::copy(sessionId.begin(),
              sessionId.end(),
              id.begin() + details::compositeTypeSize);
    std::copy(
        individualResourceId.begin(),
        individualResourceId.end(),
        id.begin() + details::compositeTypeSize + SimpleResourceId::arraySize);
    return id;
  }

  // For now, this is the only composite ID type
  static constexpr uint8_t transparentSessionType()
  {
    return 0;
  }

  uint8_t type() const
  {
    return *begin();
  }

  SimpleResourceId sessionId() const
  {
    auto first = begin() + details::compositeTypeSize;
    auto last = first + SimpleResourceId::arraySize;
    return SimpleResourceId(first, last);
  }

  SimpleResourceId individualResourceId() const
  {
    auto first =
        begin() + details::compositeTypeSize + SimpleResourceId::arraySize;
    auto last = first + SimpleResourceId::arraySize;
    return SimpleResourceId(first, last);
  };
};
}
