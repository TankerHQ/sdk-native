#pragma once

#include <Tanker/StreamInputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class GenericStreamDecryptor
{
public:
  explicit GenericStreamDecryptor(StreamInputSource source,
                                  Trustchain::ResourceId const& resourceId);

  Trustchain::ResourceId const& resourceId() const;

  tc::cotask<int64_t> operator()(uint8_t* buffer, size_t size);

private:
  StreamInputSource _source;
  Trustchain::ResourceId _resourceId;
};
}
