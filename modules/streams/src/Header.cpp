#include <Tanker/Streams/Header.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Streams
{
constexpr std::uint32_t Header::currentVersion;
constexpr std::uint32_t Header::serializedSize;
constexpr std::uint32_t Header::defaultEncryptedChunkSize;

Header::Header(std::uint32_t encryptedChunkSize,
               Trustchain::ResourceId const& resourceId,
               Crypto::AeadIv const& seed)
  : _version(Header::currentVersion),
    _encryptedChunkSize(encryptedChunkSize),
    _resourceId(resourceId),
    _seed(seed)
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

Trustchain::ResourceId const& Header::resourceId() const
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

  header._version = ss.read_varint();
  if (header._version != Header::currentVersion)
  {
    throw formatEx(
        Errc::InvalidArgument, "unsupported version: {}", header._version);
  }
  Serialization::deserialize_to(ss, header._encryptedChunkSize);
  if (header._encryptedChunkSize <
      Header::serializedSize + Crypto::Mac::arraySize)
  {
    throw formatEx(Errc::InvalidArgument,
                   "invalid encrypted chunk size in header: {}",
                   header._encryptedChunkSize);
  }
  Serialization::deserialize_to(ss, header._resourceId);
  Serialization::deserialize_to(ss, header._seed);
}

std::uint8_t* to_serialized(std::uint8_t* it, Header const& header)
{
  it = Serialization::varint_write(it, Header::currentVersion);
  it = Serialization::serialize(it, header.encryptedChunkSize());
  it = Serialization::serialize(it, header.resourceId());
  return Serialization::serialize(it, header.seed());
}
}
}
