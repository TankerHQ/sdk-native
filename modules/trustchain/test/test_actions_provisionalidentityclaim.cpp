#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Crypto/Crypto.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("ProvisionalIdentityClaim tests")
{
  SUBCASE("sign functions should return the corresponding signature")
  {
    ProvisionalIdentityClaim pic{};
    DeviceId const authorId{};
    auto const appSignatureKeyPair = Crypto::makeSignatureKeyPair();
    auto const tankerSignatureKeyPair = Crypto::makeSignatureKeyPair();
    auto const& appSignature =
        pic.signWithAppKey(appSignatureKeyPair.privateKey, authorId);
    auto const& tankerSignature =
        pic.signWithTankerKey(tankerSignatureKeyPair.privateKey, authorId);
    CHECK(appSignature == pic.authorSignatureByAppKey());
    CHECK(tankerSignature == pic.authorSignatureByTankerKey());
  }
}

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a ProvisionalIdentityClaim")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedProvisionalIdentityClaim = {
      // UserID
      0x74, 0x68, 0x65, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // AppProvisionalIdentitySignaturePublicKey
      0x74, 0x68, 0x65, 0x20,
      0x61, 0x70, 0x70, 0x20, 0x73, 0x69, 0x67, 0x20, 0x70, 0x75, 0x62, 0x20,
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // TankerProvisionalIdentitySignaturePublicKey
      0x74, 0x68, 0x65, 0x20, 0x74, 0x61, 0x6e, 0x6b,
      0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // AuthorSignatureByAppKey
      0x74, 0x68, 0x65, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x20, 0x73,
      0x69, 0x67, 0x20, 0x62, 0x79, 0x20, 0x61, 0x70, 0x70, 0x20, 0x6b, 0x65,
      0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // AuthorSignatureByTankerKey
      0x74, 0x68, 0x65, 0x20, 0x61, 0x75, 0x74, 0x68,
      0x6f, 0x72, 0x20, 0x73, 0x69, 0x67, 0x20, 0x62, 0x79, 0x20, 0x74, 0x61,
      0x6e, 0x6b, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // RecipientUserPublicKey
      0x75, 0x73, 0x65, 0x72, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // EncryptedProvisionalIdentityPrivateKeys
      0x62, 0x6f, 0x74, 0x68,
      0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x70,
      0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x73, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on
    auto const userId = make<UserId>("the user id");
    auto const appPublicSignatureKey =
        make<Crypto::PublicSignatureKey>("the app sig pub key");
    auto const tankerPublicSignatureKey =
        make<Crypto::PublicSignatureKey>("the tanker sig pub key");
    auto const signatureByAppKey =
        make<Crypto::Signature>("the author sig by app key");
    auto const signatureByTankerKey =
        make<Crypto::Signature>("the author sig by tanker key");
    auto const userPublicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("user pub key");
    auto const sealedPrivateKeys =
        make<ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>(
            "both encrypted private keys");

    ProvisionalIdentityClaim const pic{userId,
                                       appPublicSignatureKey,
                                       signatureByAppKey,
                                       tankerPublicSignatureKey,
                                       signatureByTankerKey,
                                       userPublicEncryptionKey,
                                       sealedPrivateKeys};

    CHECK(Serialization::deserialize<ProvisionalIdentityClaim>(
              serializedProvisionalIdentityClaim) == pic);
    CHECK(Serialization::serialize(pic) == serializedProvisionalIdentityClaim);
  }
}