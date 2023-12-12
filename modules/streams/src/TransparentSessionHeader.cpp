#include <Tanker/Streams/TransparentSessionHeader.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <range/v3/algorithm/contains.hpp>

using namespace Tanker::Crypto;

namespace Tanker::Streams
{
TransparentSessionHeader::TransparentSessionHeader(std::uint32_t version,
                                                   std::uint32_t encryptedChunkSize,
                                                   CompositeResourceId const& resourceId)
  : _version(version), _encryptedChunkSize(encryptedChunkSize), _resourceId(resourceId)
{
}

std::uint32_t TransparentSessionHeader::version() const
{
  return _version;
}

std::uint32_t TransparentSessionHeader::encryptedChunkSize() const
{
  return _encryptedChunkSize;
}

CompositeResourceId const& TransparentSessionHeader::resourceId() const
{
  return _resourceId;
}

void from_serialized(Serialization::SerializedSource& ss, TransparentSessionHeader& header)
{
  using namespace Tanker::Errors;

  header._version = Serialization::deserialize<uint8_t>(ss);
  if (!ranges::contains(TransparentSessionHeader::versions, header._version))
  {
    throw formatEx(Errc::InvalidArgument, "unsupported version: {}", header._version);
  }

  header._resourceId[0] = CompositeResourceId::transparentSessionType();
  auto const resourceIdData = ss.read(SimpleResourceId::arraySize + SubkeySeed::arraySize);
  std::copy(resourceIdData.begin(), resourceIdData.end(), header._resourceId.begin() + 1);

  Serialization::deserialize_to<uint32_t>(ss, header._encryptedChunkSize);
  auto paddingOverhead = header._version == 12 ? 4 : 0;
  auto chunkOverhead = Mac::arraySize + paddingOverhead;
  if (header._encryptedChunkSize < chunkOverhead)
  {
    throw formatEx(Errc::InvalidArgument, "invalid encrypted chunk size in header: {}", header._encryptedChunkSize);
  }
}

std::uint8_t* to_serialized(std::uint8_t* it, TransparentSessionHeader const& header)
{
  it = Serialization::serialize<uint8_t>(it, header.version());
  it = Serialization::serialize(it, header.resourceId().sessionId());
  it = Serialization::serialize(it, header.resourceId().individualResourceId());
  it = Serialization::serialize<uint32_t>(it, header.encryptedChunkSize());
  return it;
}
}
