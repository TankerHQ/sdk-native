#pragma once

#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
namespace Streams
{
class DecryptionStreamAdapter
{
public:
  explicit DecryptionStreamAdapter(InputSource source,
                                   Trustchain::ResourceId const& resourceId);

  Trustchain::ResourceId const& resourceId() const;

  tc::cotask<std::int64_t> operator()(std::uint8_t* buffer, std::size_t size);

private:
  InputSource _source;
  Trustchain::ResourceId _resourceId;
};
}
}
