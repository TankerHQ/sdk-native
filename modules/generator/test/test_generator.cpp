#include <doctest.h>

#include <Generator/Generator.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/KeyUsage.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Identity/Delegation.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>
#include <tconcurrent/coroutine.hpp>

#include <Helpers/Config.hpp>


using namespace Tanker;
using namespace Tanker::Generator;
using namespace std::string_literals;
using namespace Tanker::Generator::literals;

namespace
{
auto createGen()
{
  return Gen(Tanker::TestConstants::trustchainUrl(),
             Tanker::TestConstants::idToken())
      .create();
}
auto useGen(std::string truschainId, std::string privateKey)
{
  return Gen(Tanker::TestConstants::trustchainUrl(),
             Tanker::TestConstants::idToken())
      .use(truschainId, privateKey);
}
}

namespace
{
template <Crypto::KeyUsage Usage>
void testKeyPair(Crypto::KeyPair<Usage> const& key)
{
  REQUIRE_FALSE(key.privateKey.is_null());
  REQUIRE_FALSE(key.publicKey.is_null());
}

template <typename T>
void testKeys(T const& obj)
{
  testKeyPair(obj.sigKeys);
  testKeyPair(obj.encKeys);
}

void testDelegation(Identity::Delegation const& delegation)
{
  CHECK_FALSE(delegation.ephemeralKeyPair.publicKey.is_null());
  CHECK_FALSE(delegation.ephemeralKeyPair.privateKey.is_null());
  CHECK_FALSE(delegation.userId.is_null());
  CHECK_FALSE(delegation.signature.is_null());
}

struct UniqueTc
{
  Generator::Gen gen = createGen();
};
}

TEST_CASE("Create a Generator")
{
  SUBCASE("create Do not throw")
  {
    REQUIRE_NOTHROW(createGen());
  }
  SUBCASE("get it")
  {
    auto gen = createGen();
  }
  SUBCASE("use it")
  {
    Gen gen1 = createGen();
    auto pk = fmt::format("{}", gen1.keyPair().privateKey);
    REQUIRE_NOTHROW(useGen(gen1.trustchainId(), pk));
  }
}

TEST_CASE_FIXTURE(UniqueTc, "UserGenerator")
{
  SUBCASE("Does not throw")
  {
    REQUIRE_NOTHROW(gen.make(1_users));
  }
  SUBCASE("the user is valid")
  {
    auto uGen = gen.make(1_users);
    SUBCASE("with a random uuid")
    {
      CHECK(cppcodec::base64_rfc4648::encode(uGen.front().author) ==
            gen.trustchainId());
      CHECK_FALSE(uGen.front().obfuscatedId.is_null());
      testDelegation(uGen.front().delegation);
      testKeys(uGen.front());
    }
  }
  SUBCASE("generic API")
  {
    SUBCASE("Does not throw")
    {
      REQUIRE_NOTHROW(gen.make(1_users));
    }
    SUBCASE("with a random uuid")
    {
      auto uGen = gen.make(5_users);
      CHECK(cppcodec::base64_rfc4648::encode(uGen.front().author) ==
            gen.trustchainId());
      CHECK_FALSE(uGen.front().obfuscatedId.is_null());
      testDelegation(uGen.front().delegation);
      testKeys(uGen.front());
    }
  }
}

TEST_CASE_FIXTURE(UniqueTc, "Create a device from another device")
{
  auto user = gen.makeUser();
  auto device = user.makeDevice();
  testDelegation(device.delegation);
  testKeys(device);
  CHECK_FALSE(device.author.is_null());
  CHECK_FALSE(device.obfuscatedId.is_null());
}

TEST_CASE_FIXTURE(UniqueTc, "Create a user with a device chain")
{
  auto devices = gen.makeUser().with(3_devices);
  REQUIRE(devices.size() == 3);
  for (auto const& device : devices)
  {
    testDelegation(device.delegation);
    testKeys(device);
    CHECK_FALSE(device.author.is_null());
    CHECK_FALSE(device.obfuscatedId.is_null());
  }
}

TEST_CASE_FIXTURE(UniqueTc, "Shares")
{
  auto const users = gen.make(2_users);
  SUBCASE("Does not throw")
  {
    REQUIRE_NOTHROW(Share(users[0], users[1]));
    SUBCASE("KeyPublishToDevice is valid")
    {
      auto kp = Share(users[0], users[1]);
      FAST_CHECK_UNARY_FALSE(kp.res.key.empty());
      FAST_CHECK_UNARY_FALSE(kp.res.mac.is_null());
      FAST_CHECK_UNARY_FALSE(kp.sender.is_null());
      FAST_CHECK_UNARY_FALSE(kp.recipient.is_null());
      FAST_CHECK_UNARY_FALSE(kp.privateSigKey.is_null());
      SUBCASE("push it")
      {
        auto kp = Share(users[0], users[1]);
        CHECK_NOTHROW(gen.push(users[0]));
        CHECK_NOTHROW(gen.push(users[1]));
        CHECK_NOTHROW(gen.push(kp));
      }
    }
    SUBCASE("Publish a key to 10 users")
    {
      auto users = gen.make(10_users);
      REQUIRE_EQ(users.size(), 10);
      auto beg = begin(users);
      REQUIRE_NOTHROW(gen.dispatch(beg, end(users)));
      auto& alice = *beg;
      auto shares = gen.makeShares(alice, beg, end(users));
      REQUIRE_EQ(shares.size(), 10);
      REQUIRE_NOTHROW(gen.dispatch(begin(shares), end(shares)));
    }
  }
}

TEST_CASE_FIXTURE(UniqueTc, "Create users")
{
  SUBCASE("Create 10 user")
  {
    auto const& users = gen.make(10_users);
    FAST_REQUIRE_EQ(users.size(), 10);
    REQUIRE_NOTHROW(gen.dispatch(begin(users), end(users)));
  }
  SUBCASE("Create 100 user")
  {
    auto const users = gen.make(100_users);
    REQUIRE(users.size() == 100);
    REQUIRE_NOTHROW(gen.dispatch(begin(users), end(users)));
  }
  SUBCASE("Device chain")
  {
    auto const user = std::move(gen.make(1_users).front());
    REQUIRE_NOTHROW(gen.push(user));
    SUBCASE("Created from a user")
    {
      auto const device0 = user.makeDevice();
      SUBCASE("Delegation is valid")
      {
        testDelegation(device0.delegation);
        testKeys(device0);
        REQUIRE_FALSE(device0.author.is_null());
      }
    }
    SUBCASE("Created from another device")
    {
      auto const device0 = user.makeDevice();
      SUBCASE("Delegation is valid")
      {
        testDelegation(device0.delegation);
        testKeys(device0);
        REQUIRE_FALSE(device0.author.is_null());
      }
      SUBCASE("Can be pushed")
      {
        CHECK_NOTHROW(gen.push(device0));
      }
    }
  }
}
