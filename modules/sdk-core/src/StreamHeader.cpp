#include <Tanker/StreamHeader.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
constexpr std::uint32_t StreamHeader::currentVersion;
constexpr std::uint32_t StreamHeader::serializedSize;
constexpr std::uint32_t StreamHeader::defaultEncryptedChunkSize;

StreamHeader::StreamHeader(std::uint32_t encryptedChunkSize,
                           Trustchain::ResourceId const& resourceId,
                           Crypto::AeadIv const& seed)
  : _version(StreamHeader::currentVersion),
    _encryptedChunkSize(encryptedChunkSize),
    _resourceId(resourceId),
    _seed(seed)
{
}

std::uint32_t StreamHeader::version() const
{
  return _version;
}

std::uint32_t StreamHeader::encryptedChunkSize() const
{
  return _encryptedChunkSize;
}

Trustchain::ResourceId const& StreamHeader::resourceId() const
{
  return _resourceId;
}

Crypto::AeadIv const& StreamHeader::seed() const
{
  return _seed;
}

void from_serialized(Serialization::SerializedSource& ss, StreamHeader& header)
{
  using namespace Tanker::Errors;

  header._version = ss.read_varint();
  if (header._version != StreamHeader::currentVersion)
  {
    throw formatEx(
        Errc::InvalidArgument, "unsupported version: {}", header._version);
  }
  Serialization::deserialize_to(ss, header._encryptedChunkSize);
  if (header._encryptedChunkSize <
      StreamHeader::serializedSize + Crypto::Mac::arraySize)
  {
    throw formatEx(Errc::InvalidArgument,
                   "invalid encrypted chunk size in header: {}",
                   header._encryptedChunkSize);
  }
  Serialization::deserialize_to(ss, header._resourceId);
  Serialization::deserialize_to(ss, header._seed);
}

std::uint8_t* to_serialized(std::uint8_t* it, StreamHeader const& header)
{
  it = Serialization::varint_write(it, StreamHeader::currentVersion);
  it = Serialization::serialize(it, header.encryptedChunkSize());
  it = Serialization::serialize(it, header.resourceId());
  return Serialization::serialize(it, header.seed());
}
}
