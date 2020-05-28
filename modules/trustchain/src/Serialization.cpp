#include <Tanker/Trustchain/Serialization.hpp>

#include <Tanker/Trustchain/Errors/Errc.hpp>

namespace Tanker::Trustchain
{
void deserializeBlockVersion(Serialization::SerializedSource& ss)
{
  auto const version = ss.read_varint();

  if (version != 1)
  {
    throw Errors::formatEx(
        Errc::InvalidBlockVersion, "unsupported block version: {}", version);
  }
}

void deserializeBlockNature(Serialization::SerializedSource& ss,
                            Actions::Nature expected)
{
  auto const nature = static_cast<Actions::Nature>(ss.read_varint());
  if (nature != expected)
  {
    throw Errors::formatEx(Errc::InvalidBlockVersion,
                           "wrong block nature: expected {}, got {}",
                           expected,
                           nature);
  }
}
}
