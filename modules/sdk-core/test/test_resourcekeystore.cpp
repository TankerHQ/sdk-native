#include <Tanker/ResourceKeys/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch_test_macros.hpp>
#include <mgs/base64.hpp>

using namespace Tanker;

TEST_CASE("Resource Keys Store")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath,
                                            DataStore::MemoryPath);

  ResourceKeys::Store keys({}, db.get());

  SECTION("it should not find a non-existent key")
  {
    auto const unexistentMac = make<Crypto::SimpleResourceId>("unexistent");

    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(keys.getKey(unexistentMac)),
                                  Errors::Errc::InvalidArgument);
  }

  SECTION("it should find a key that was inserted")
  {
    auto const resourceId = make<Crypto::SimpleResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");

    AWAIT_VOID(keys.putKey(resourceId, key));
    auto const key2 = AWAIT(keys.getKey(resourceId));

    CHECK(key == key2);
  }

  SECTION("it should ignore a duplicate key and keep the first")
  {
    auto const resourceId = make<Crypto::SimpleResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");
    auto const key2 = make<Crypto::SymmetricKey>("mykey2");

    AWAIT_VOID(keys.putKey(resourceId, key));
    AWAIT_VOID(keys.putKey(resourceId, key2));
    auto const gotKey = AWAIT(keys.getKey(resourceId));

    CHECK(key == gotKey);
  }
}
