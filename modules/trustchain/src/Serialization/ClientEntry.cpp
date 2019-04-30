#include <Tanker/Trustchain/ClientEntry.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace Tanker
{
namespace Trustchain
{
std::uint8_t* to_serialized(std::uint8_t* it, ClientEntry const& ce)
{
  auto const natureInt = static_cast<unsigned>(ce.nature());
  auto const version = 1;

  it = Serialization::varint_write(it, version);
  it = Serialization::varint_write(it, std::uint64_t{});
  it = Serialization::serialize(it, ce.trustchainId());
  it = Serialization::varint_write(it, natureInt);
  auto const& serializedPayload = ce.serializedPayload();
  it = Serialization::varint_write(it, serializedPayload.size());
  it = std::copy(serializedPayload.begin(), serializedPayload.end(), it);
  it = Serialization::serialize(it, ce.parentHash());
  return Serialization::serialize(it, ce.signature());
}

std::size_t serialized_size(ClientEntry const& ce)
{
  auto const version = 1;
  auto const natureInt = static_cast<unsigned>(ce.nature());
  // we do not care about the block index client-side
  // but we must put it in the wire format
  std::uint64_t const index{};
  auto const payloadSize = ce.serializedPayload().size();

  return Serialization::varint_size(version) +
         Serialization::varint_size(index) +
         Serialization::varint_size(natureInt) +
         Serialization::varint_size(payloadSize) + TrustchainId::arraySize +
         payloadSize + Crypto::Hash::arraySize + Crypto::Signature::arraySize;
}
}
}
