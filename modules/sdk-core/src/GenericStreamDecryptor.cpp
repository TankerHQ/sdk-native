#include <Tanker/GenericStreamDecryptor.hpp>

namespace Tanker
{
GenericStreamDecryptor::GenericStreamDecryptor(
    StreamInputSource source, Trustchain::ResourceId const& resourceId)
  : _source(std::move(source)), _resourceId(resourceId)
{
}

Trustchain::ResourceId const& GenericStreamDecryptor::resourceId() const
{
  return _resourceId;
}

tc::cotask<int64_t> GenericStreamDecryptor::operator()(uint8_t* buffer,
                                                       size_t size)
{
  return _source(buffer, size);
}
}
