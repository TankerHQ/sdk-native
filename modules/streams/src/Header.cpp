#include <Tanker/Streams/Header.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <range/v3/algorithm/contains.hpp>

namespace Tanker
{
namespace Streams
{
Header::Header(std::uint32_t version,
               std::uint32_t encryptedChunkSize,
               Crypto::SimpleResourceId const& resourceId,
               Crypto::AeadIv const& seed)
  : _version(version), _encryptedChunkSize(encryptedChunkSize), _resourceId(resourceId), _seed(seed)
{
}

std::uint32_t Header::version() const
{
  return _version;
}

std::uint32_t Header::encryptedChunkSize() const
{
  return _encryptedChunkSize;
}

Crypto::SimpleResourceId const& Header::resourceId() const
{
  return _resourceId;
}

Crypto::AeadIv const& Header::seed() const
{
  return _seed;
}

void from_serialized(Serialization::SerializedSource& ss, Header& header)
{
  using namespace Tanker::Errors;

  header._version = Serialization::deserialize<uint8_t>(ss);
  if (!ranges::contains(Header::versions, header._version))
  {
    throw formatEx(Errc::InvalidArgument, "unsupported version: {}", header._version);
  }
  Serialization::deserialize_to<uint32_t>(ss, header._encryptedChunkSize);
  if (header._encryptedChunkSize < Header::serializedSize + Crypto::Mac::arraySize)
  {
    throw formatEx(Errc::InvalidArgument, "invalid encrypted chunk size in header: {}", header._encryptedChunkSize);
  }
  Serialization::deserialize_to(ss, header._resourceId);
  Serialization::deserialize_to(ss, header._seed);
}

std::uint8_t* to_serialized(std::uint8_t* it, Header const& header)
{
  it = Serialization::serialize<uint8_t>(it, header.version());
  it = Serialization::serialize<uint32_t>(it, header.encryptedChunkSize());
  it = Serialization::serialize(it, header.resourceId());
  return Serialization::serialize(it, header.seed());
}
}
}
