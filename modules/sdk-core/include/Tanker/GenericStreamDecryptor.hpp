#pragma once

#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstdint>

namespace Tanker
{
class GenericStreamDecryptor
{
public:
  explicit GenericStreamDecryptor(Streams::InputSource source,
                                  Trustchain::ResourceId const& resourceId);

  Trustchain::ResourceId const& resourceId() const;

  tc::cotask<int64_t> operator()(uint8_t* buffer, size_t size);

private:
  Streams::InputSource _source;
  Trustchain::ResourceId _resourceId;
};
}
