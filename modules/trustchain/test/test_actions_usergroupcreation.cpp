#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest/doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a UserGroupCreation1")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedUserGroupCreation = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x0a,
      // varint payload size
      0xd1, 0x03,
      // public signature key
      0x70, 0x75, 0x62, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x20,
      0x65, 0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // encrypted group private signature key
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
      0x64, 0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint
      0x02,
      // public user encryption key 1
      0x70, 0x75, 0x62,
      0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private encryption key 1
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
      0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69,
      0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00,
      // public user encryption key 2
      0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x20,
      0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private encryption key 2
      0x73, 0x65, 0x63,
      0x6f, 0x6e, 0x64, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
      0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69, 0x76,
      0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00,
      // self signature
      0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69,
      0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

    auto const publicSignatureKey =
        make<Crypto::PublicSignatureKey>("pub sig key");
    auto const publicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("pub enc key");
    auto const sealedPrivateSignatureKey =
        make<Crypto::SealedPrivateSignatureKey>("encrypted priv sig key");
    UserGroupCreation1::SealedPrivateEncryptionKeysForUsers const
        sealedPrivateEncryptionKeysForUsers{
            {make<Crypto::PublicEncryptionKey>("pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "encrypted group priv key")},
            {make<Crypto::PublicEncryptionKey>("second pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "second encrypted group priv key")}};
    auto const selfSignature = make<Crypto::Signature>("self signature");
    auto const hash = mgs::base64::decode<Crypto::Hash>(
        "SKeSWc4BdOBuGY31q5IzhIBEzUy7veyLTbtNyHK8twE=");

    UserGroupCreation1 const ugc{trustchainId,
                                 publicSignatureKey,
                                 publicEncryptionKey,
                                 sealedPrivateSignatureKey,
                                 sealedPrivateEncryptionKeysForUsers,
                                 selfSignature,
                                 author,
                                 hash,
                                 signature};

    CHECK(Serialization::serialize(ugc) == serializedUserGroupCreation);
    CHECK(Serialization::deserialize<UserGroupCreation1>(
              serializedUserGroupCreation) == ugc);
  }

  SUBCASE("it should serialize/deserialize a UserGroupCreation2")
  {
    auto const userGroupCreation = UserGroupCreation2{
        make<TrustchainId>("trustchain id"),
        make<Crypto::PublicSignatureKey>("pub sig key"),
        make<Crypto::PublicEncryptionKey>("pub enc key"),
        make<Crypto::SealedPrivateSignatureKey>("encrypted priv sig key"),
        {
            {make<UserId>("user id"),
             make<Crypto::PublicEncryptionKey>("pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "encrypted group priv key")},
            {make<UserId>("second user id"),
             make<Crypto::PublicEncryptionKey>("second pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "second encrypted group priv key")},
        },
        {
            {
                make<Crypto::PublicSignatureKey>("app provisional user key"),
                make<Crypto::PublicSignatureKey>("tanker provisional user key"),
                make<Crypto::TwoTimesSealedPrivateEncryptionKey>(
                    "provisional user encrypted group priv key"),
            },
            {
                make<Crypto::PublicSignatureKey>(
                    "2nd app provisional user key"),
                make<Crypto::PublicSignatureKey>(
                    "2nd tanker provisional user key"),
                make<Crypto::TwoTimesSealedPrivateEncryptionKey>(
                    "2nd provisional user encrypted group priv key"),
            },
        },
        make<Crypto::Signature>("self signature"),
        make<Crypto::Hash>("author"),
        mgs::base64::decode<Crypto::Hash>(
            "GYTC0cvLKOYIwxn8RY9QpFUTYeybjIHUPy8x40EjFH0="),
        make<Crypto::Signature>("sig"),
    };

    std::vector<uint8_t> const payload{
        // clang-format off
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x0f,
      // varint payload size
      0x92, 0x07,
      // public signature key
      0x70, 0x75, 0x62, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private signature key
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x70, 0x72,
      0x69, 0x76, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // Varint
      0x02,
      // user ID 1
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public user encryption key 1
      0x70, 0x75, 0x62, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private encryption key 1
      0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72,
      0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user ID 2
      0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20,
      0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public user encryption key 2
      0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x20, 0x75,
      0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private encryption key 2
      0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79,
      0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70,
      0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Varint
      0x02,
      // public app encryption key 1
      0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
      0x6e, 0x61, 0x6c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public tanker encryption key 1
      0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69,
      0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20,
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
      // encrypted group private encryption key 1
      0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20,
      0x75, 0x73, 0x65, 0x72, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
      0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69,
      0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // provisional user app encryption key 2
      0x32, 0x6e, 0x64, 0x20, 0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76,
      0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x75, 0x73, 0x65, 0x72,
      0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      // provisional user tanker encryption key 2
      0x32, 0x6e, 0x64, 0x20, 0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70,
      0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x75,
      0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00,
      // encrypted group private encryption key 2
      0x32, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
      0x6e, 0x61, 0x6c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x65, 0x6e, 0x63,
      0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70,
      0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // self signature
      0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
      0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
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
        // clang-format on
    };

    CHECK(Serialization::serialize(userGroupCreation) == payload);
    CHECK(Serialization::deserialize<UserGroupCreation2>(payload) ==
          userGroupCreation);
  }

  SUBCASE("it should serialize/deserialize a UserGroupCreation3")
  {
    auto const userGroupCreation = UserGroupCreation3{
        make<TrustchainId>("trustchain id"),
        make<Crypto::PublicSignatureKey>("pub sig key"),
        make<Crypto::PublicEncryptionKey>("pub enc key"),
        make<Crypto::SealedPrivateSignatureKey>("encrypted priv sig key"),
        {
            {make<UserId>("user id"),
             make<Crypto::PublicEncryptionKey>("pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "encrypted group priv key")},
            {make<UserId>("second user id"),
             make<Crypto::PublicEncryptionKey>("second pub user key"),
             make<Crypto::SealedPrivateEncryptionKey>(
                 "second encrypted group priv key")},
        },
        {
            {
                make<Crypto::PublicSignatureKey>("app provisional sig key"),
                make<Crypto::PublicSignatureKey>("tanker provisional sig key"),
                make<Crypto::PublicEncryptionKey>("app provisional enc key"),
                make<Crypto::PublicEncryptionKey>("tanker provisional enc key"),
                make<Crypto::TwoTimesSealedPrivateEncryptionKey>(
                    "provisional user encrypted group priv key"),
            },
            {
                make<Crypto::PublicSignatureKey>("2nd app provisional sig key"),
                make<Crypto::PublicSignatureKey>(
                    "2nd tanker provisional sig key"),
                make<Crypto::PublicEncryptionKey>(
                    "2nd app provisional enc key"),
                make<Crypto::PublicEncryptionKey>(
                    "2nd tanker provisional enc key"),
                make<Crypto::TwoTimesSealedPrivateEncryptionKey>(
                    "2nd provisional user encrypted group priv key"),
            },
        },
        make<Crypto::Signature>("self signature"),
        make<Crypto::Hash>("author"),
        mgs::base64::decode<Crypto::Hash>(
            "LKF4FeNTpFhfalGxL+j2QgdlM76JD8ZKb/1uLmuhWaw="),
        make<Crypto::Signature>("sig"),
    };

    std::vector<uint8_t> const payload{
        // clang-format off
        // varint version
        0x01,
        // varint index
        0x00,
        // trustchain id
        0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // varint nature
        0x11,
        // varint payload size
        0x92, 0x08,
        // public signature key
        0x70, 0x75, 0x62, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public encryption key
        0x70, 0x75, 0x62, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // encrypted group private signature key
        0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x70, 0x72,
        0x69, 0x76, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // Varint
        0x02,
        // user ID 1
        0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public user encryption key 1
        0x70, 0x75, 0x62, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // encrypted group private encryption key 1
        0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72,
        0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // user ID 2
        0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20,
        0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public user encryption key 2
        0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x75, 0x62, 0x20, 0x75,
        0x73, 0x65, 0x72, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // encrypted group private encryption key 2
        0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79,
        0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70,
        0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Varint
        0x02,
        // public app signature key 1
        0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
        0x6e, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public tanker signature key 1
        0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69,
        0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x20, 0x6b,
        0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public app encryption key 1
        0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
        0x6e, 0x61, 0x6c, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // public tanker encryption key 1
        0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69,
        0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
        0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // encrypted group private encryption key 1
        0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20,
        0x75, 0x73, 0x65, 0x72, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
        0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x20, 0x70, 0x72, 0x69,
        0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // provisional user app signature key 2
        0x32, 0x6e, 0x64, 0x20, 0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76,
        0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x20,
        0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
        // provisional user tanker signature key 2
        0x32, 0x6e, 0x64, 0x20, 0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70,
        0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x73,
        0x69, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00,
        // provisional user app encryption key 2
        0x32, 0x6e, 0x64, 0x20, 0x61, 0x70, 0x70, 0x20, 0x70, 0x72, 0x6f, 0x76,
        0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x65, 0x6e, 0x63, 0x20,
        0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00,
        // provisional user tanker encryption key 2
        0x32, 0x6e, 0x64, 0x20, 0x74, 0x61, 0x6e, 0x6b, 0x65, 0x72, 0x20, 0x70,
        0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x65,
        0x6e, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00,
        // encrypted group private encryption key 2
        0x32, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f,
        0x6e, 0x61, 0x6c, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x65, 0x6e, 0x63,
        0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x20, 0x67, 0x72, 0x6f, 0x75, 0x70,
        0x20, 0x70, 0x72, 0x69, 0x76, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // self signature
        0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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
        // clang-format on
    };

    CHECK(Serialization::serialize(userGroupCreation) == payload);
    CHECK(Serialization::deserialize<UserGroupCreation3>(payload) ==
          userGroupCreation);
  }
}
