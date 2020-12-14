#include <Tanker/Trustchain/Serialization.hpp>

#include <Tanker/Trustchain/Errors/Errc.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

namespace Tanker::Trustchain
{
static constexpr auto blockVersion = 1;

Actions::Nature getBlockNature(gsl::span<std::uint8_t const> block)
{
  // The layout is [version byte | index varint | trustchain id 32-bytes |
  // nature byte]

  if (block.size() < 2)
    throw Errors::formatEx(Errc::InvalidBlockVersion, "block too small");
  if (block[0] != blockVersion)
    throw Errors::formatEx(
        Errc::InvalidBlockVersion, "unsupported block version: {}", block[0]);

  auto const rest = Serialization::varint_read(block.subspan(1)).second;
  if (rest.size() < TrustchainId::arraySize + 1)
    throw Errors::formatEx(Errc::InvalidBlockVersion, "block too small");

  return static_cast<Actions::Nature>(rest[TrustchainId::arraySize]);
}

void deserializeBlockVersion(Serialization::SerializedSource& ss)
{
  auto const version = ss.read_varint();

  if (version != blockVersion)
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
    throw Errors::formatEx(Errc::InvalidBlockNature,
                           "wrong block nature: expected {}, got {}",
                           expected,
                           nature);
  }
}
}
