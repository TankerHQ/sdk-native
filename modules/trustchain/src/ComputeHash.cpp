#include <Tanker/Trustchain/ComputeHash.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <algorithm>
#include <vector>

namespace Tanker::Trustchain
{
Crypto::Hash computeHash(Actions::Nature nature,
                         Crypto::Hash const& author,
                         gsl::span<std::uint8_t const> serializedPayload)
{
  auto const natureInt = static_cast<unsigned>(nature);
  std::vector<std::uint8_t> buffer(Serialization::varint_size(natureInt) + author.size() + serializedPayload.size());
  auto it = buffer.data();
  it = Serialization::varint_write(it, natureInt);
  it = Serialization::serialize(it, author);
  std::copy(serializedPayload.begin(), serializedPayload.end(), it);

  return Crypto::generichash(buffer);
}
}
