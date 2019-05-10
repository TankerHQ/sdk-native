#include <doctest.h>

#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Buffers.hpp>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::ResourceId;
using namespace Tanker;

TEST_CASE("it should serialize/deserialize a Block")
{
  Block before;
  before.trustchainId = make<Trustchain::TrustchainId>("the trustchain ID !");
  before.index = 12345;
  before.author = make<Crypto::Hash>("block author");
  before.payload = std::vector<uint8_t>{10, 11, 12, 88, 191, 16};
  before.signature = make<Crypto::Signature>("this is a signature");

  Block const after =
      Serialization::deserialize<Block>(Serialization::serialize(before));

  CHECK(before == after);
}
