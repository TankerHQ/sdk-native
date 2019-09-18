#include <Tanker/GenericDecryptionStream.hpp>

namespace Tanker
{
GenericDecryptionStream::GenericDecryptionStream(
    Streams::InputSource source, Trustchain::ResourceId const& resourceId)
  : _source(std::move(source)), _resourceId(resourceId)
{
}

Trustchain::ResourceId const& GenericDecryptionStream::resourceId() const
{
  return _resourceId;
}

tc::cotask<int64_t> GenericDecryptionStream::operator()(uint8_t* buffer,
                                                       size_t size)
{
  return _source(buffer, size);
}
}
