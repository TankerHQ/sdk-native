#include <Tanker/Block.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <string>
#include <tuple>

using namespace std::string_literals;

using json = nlohmann::json;

namespace Tanker
{
bool operator==(Block const& l, Block const& r)
{
  return std::tie(l.trustchainId, l.index, l.author, l.payload, l.signature) ==
         std::tie(r.trustchainId, r.index, r.author, r.payload, r.signature);
}

bool operator!=(Block const& l, Block const& r)
{
  return !(l == r);
}

Crypto::Hash Block::hash() const
{
  auto const natureInt = static_cast<unsigned>(this->nature);

  std::vector<uint8_t> hashedPayload;
  hashedPayload.resize(Serialization::varint_size(natureInt) + author.size() +
                       payload.size());
  auto it = hashedPayload.data();
  it = Serialization::varint_write(it, natureInt);
  it = Serialization::serialize(it , author);
  std::copy(payload.begin(), payload.end(), it);

  return Crypto::generichash(hashedPayload);
}

bool Block::verifySignature(
    Crypto::PublicSignatureKey const& publicSignatureKey) const
{
  return Crypto::verify(hash(), signature, publicSignatureKey);
}

std::size_t serialized_size(Block const& b)
{
  auto const version = 1;
  auto const natureInt = static_cast<unsigned>(b.nature);

  return Serialization::varint_size(version) +
         Serialization::varint_size(b.index) +
         Serialization::varint_size(natureInt) +
         Serialization::varint_size(b.payload.size()) + b.trustchainId.size() +
         b.payload.size() + b.author.size() + b.signature.size();
}

void from_serialized(Serialization::SerializedSource& ss, Block& b)
{
  auto const version = ss.read_varint();

  if (version != 1)
    throw std::runtime_error("unsupported block version: " +
                             std::to_string(version));
  b.index = ss.read_varint();
  b.trustchainId = Serialization::deserialize<TrustchainId>(ss);
  b.nature = static_cast<Nature>(ss.read_varint());

  auto const payloadSize = ss.read_varint();
  auto const payloadSpan = ss.read(payloadSize);

  b.payload.insert(b.payload.begin(), payloadSpan.begin(), payloadSpan.end());
  b.author = Serialization::deserialize<Crypto::Hash>(ss);
  b.signature = Serialization::deserialize<Crypto::Signature>(ss);
}

std::uint8_t* to_serialized(std::uint8_t* it, Block const& b)
{
  auto const natureInt = static_cast<unsigned>(b.nature);
  auto const version = 1;

  it = Serialization::varint_write(it, version);
  it = Serialization::varint_write(it, b.index);
  it = Serialization::serialize(it, b.trustchainId);
  it = Serialization::varint_write(it, natureInt);
  // payload is a vector<uint8_t>, cannot call serialize with it
  it = Serialization::varint_write(it, b.payload.size());
  it = std::copy(b.payload.begin(), b.payload.end(), it);
  it = Serialization::serialize(it, b.author);
  return Serialization::serialize(it, b.signature);
}

void to_json(nlohmann::json& j, Block const& b)
{
  j["trustchainId"] = b.trustchainId;
  j["index"] = b.index;
  j["author"] = b.author;
  j["nature"] = b.nature;
  j["payload"] = base64::encode(b.payload);
  j["signature"] = b.signature;
  j["hash"] = b.hash();
}
}
