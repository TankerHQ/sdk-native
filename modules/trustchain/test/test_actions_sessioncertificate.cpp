#include <Tanker/Trustchain/Actions/SessionCertificate.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest/doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a SessionCertificate")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedSessionCertificate = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x13,
      // varint payload size
      0x49,
      // session pub sig key
      0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x73, 0x69, 0x67, 0x20,
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // timestamp
      0xc0, 0xd5, 0x62, 0x61, 0x00, 0x00, 0x00, 0x00,
      // verification method type varint
      0x01,
      // verification method hashed target
      0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20, 0x65, 0x6d, 0x61, 0x69, 0x6c,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // author
      0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // signature
      0x73, 0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    auto const trustchainId = make<TrustchainId>("trustchain id");
    auto const author = make<Crypto::Hash>("author");
    auto const signature = make<Crypto::Signature>("sig");

    auto const sessionSignaturKey =
        make<Crypto::PublicSignatureKey>("session sig key");
    auto const timestamp = 1633867200;
    auto const verifType = VerificationMethodType::Email;
    auto const verifTarget = make<Crypto::Hash>("hashed email");

    auto const hash = mgs::base64::decode<Crypto::Hash>(
        "d88Au3e2dVr5tMtayfyYaVNaokR0CCl92Pq1JZhl6Mw=");
    SessionCertificate const sc(trustchainId,
                                sessionSignaturKey,
                                timestamp,
                                verifType,
                                verifTarget,
                                author,
                                hash,
                                signature);

    CHECK(Serialization::serialize(sc) == serializedSessionCertificate);
    CHECK(Serialization::deserialize<SessionCertificate>(
              serializedSessionCertificate) == sc);
  }
}
