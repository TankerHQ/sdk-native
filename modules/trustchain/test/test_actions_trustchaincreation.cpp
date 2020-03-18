#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("TrustchainCreation tests")
{
  Crypto::PublicSignatureKey const publicSignatureKey{};
  TrustchainCreation tc(publicSignatureKey);

  CHECK(tc.nature() == Nature::TrustchainCreation);
  CHECK(tc.publicSignatureKey() == publicSignatureKey);
}

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a TrustchainCreation")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedTrustchainCreation = {
      // public signature key
      0x66, 0x98, 0x23, 0xe7, 0xc5, 0x0e, 0x13, 0xe0, 0xed, 0x4a, 0x56, 0x91,
      0xc6, 0x63, 0xc7, 0xeb, 0x1b, 0xd6, 0x53, 0x12, 0xd4, 0x8d, 0x21, 0xd4,
      0x86, 0x76, 0x0f, 0x04, 0x85, 0x7d, 0xf0, 0xef
    };
    // clang-format on
    TrustchainCreation const tc{
        Crypto::PublicSignatureKey(serializedTrustchainCreation)};

    CHECK(Serialization::serialize(tc) == serializedTrustchainCreation);
    CHECK(Serialization::deserialize<TrustchainCreation>(
              serializedTrustchainCreation) == tc);
  }
}
