#include <Tanker/Streams/DecryptionStreamAdapter.hpp>

namespace Tanker
{
namespace Streams
{
DecryptionStreamAdapter::DecryptionStreamAdapter(
    Streams::InputSource source, Trustchain::ResourceId const& resourceId)
  : _source(std::move(source)), _resourceId(resourceId)
{
}

Trustchain::ResourceId const& DecryptionStreamAdapter::resourceId() const
{
  return _resourceId;
}

tc::cotask<std::int64_t> DecryptionStreamAdapter::operator()(
    gsl::span<std::uint8_t> buffer)
{
  return _source(buffer);
}
}
}
