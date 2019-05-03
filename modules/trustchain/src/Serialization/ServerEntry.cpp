#include <Tanker/Trustchain/ServerEntry.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/detail/ComputeHash.hpp>

#include <stdexcept>
#include <string>

namespace Tanker
{
namespace Trustchain
{
void from_serialized(Serialization::SerializedSource& ss, ServerEntry& se)
{
  auto const version = ss.read_varint();

  if (version != 1)
    throw std::runtime_error("unsupported block version: " +
                             std::to_string(version));
  se._index = ss.read_varint();
  Serialization::deserialize_to(ss, se._trustchainId);
  auto const nature = static_cast<Actions::Nature>(ss.read_varint());

  auto const payloadSize = ss.read_varint();
  auto const payloadSpan = ss.read(payloadSize);

  se._action = Action::deserialize(nature, payloadSpan);
  Serialization::deserialize_to(ss, se._author);
  Serialization::deserialize_to(ss, se._signature);
  se._hash = detail::computeHash(nature, se._author, payloadSpan);
}
}
}
