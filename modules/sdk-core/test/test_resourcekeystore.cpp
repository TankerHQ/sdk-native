#include <Tanker/ResourceKeys/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>
#include <mgs/base64.hpp>

using namespace Tanker;

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>

TEST_CASE("Resource Keys Store")
{
  auto db = AWAIT(DataStore::createDatabase(":memory:"));

  ResourceKeys::Store keys(&db);

  SUBCASE("it should not find a non-existent key")
  {
    auto const unexistentMac = make<Trustchain::ResourceId>("unexistent");

    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(keys.getKey(unexistentMac)),
                                  Errors::Errc::InvalidArgument);
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const resourceId = make<Trustchain::ResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");

    AWAIT_VOID(keys.putKey(resourceId, key));
    auto const key2 = AWAIT(keys.getKey(resourceId));

    CHECK(key == key2);
  }

  SUBCASE("it should ignore a duplicate key and keep the first")
  {
    auto const resourceId = make<Trustchain::ResourceId>("mymac");
    auto const key = make<Crypto::SymmetricKey>("mykey");
    auto const key2 = make<Crypto::SymmetricKey>("mykey2");

    AWAIT_VOID(keys.putKey(resourceId, key));
    AWAIT_VOID(keys.putKey(resourceId, key2));
    auto const gotKey = AWAIT(keys.getKey(resourceId));

    CHECK_EQ(key, gotKey);
  }
}
