#pragma once

#include <catch2/catch_test_macros.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/DataStoreTestUtils.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/UniquePath.hpp>

template <typename T>
void runDataStoreTests(T& backend, std::string_view writablePath)
{
  using CacheResult = std::vector<std::optional<std::vector<uint8_t>>>;

  using namespace Tanker;
  using namespace Tanker::DataStore;

  Tanker::UniquePath testtmp{std::string(writablePath)};
  auto store = backend.open(testtmp.path, testtmp.path);

  SECTION("Put and get device")
  {
    SECTION("returns nullopt when there is no device")
    {
      CHECK(!store->findSerializedDevice());
    }

    SECTION("can put and get a device")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      CHECK(store->findSerializedDevice() == device);
    }

    SECTION("can close and reopen the db")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));

      // We need to close the DB before we can reopen it
      store.reset();
      store = backend.open(testtmp.path, testtmp.path);

      CHECK(store->findSerializedDevice() == device);
    }

    SECTION("can overwrite and get a device")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      CHECK(store->findSerializedDevice() == device);
    }
  }

  SECTION("Put and get cache values")
  {
    SECTION("returns nothing if the value is not there")
    {
      auto const key = make_buffer("test key");
      auto const keys = {gsl::make_span(key)};
      std::vector<std::optional<std::vector<uint8_t>>> expected{std::nullopt};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("puts no value at all")
    {
      auto const keyValues = makeKeyValues({});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));
    }

    SECTION("puts a binary value and gets it back")
    {
      char const key[] = "test\0 key";
      char const value[] = "test\0 value";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("puts and gets multiple values at once, respecting order")
    {
      auto const key = "test key 1";
      auto const key2 = "test key 2";
      auto const unknownKey = "unknown";
      auto const value = "test value";
      auto const value2 = "test another value";
      auto const keyValues = makeKeyValues({{key, value}, {key2, value2}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      // invert them, just to check that the order is respected
      auto const keys = makeKeys({key2, unknownKey, key});
      CacheResult expected{make_buffer(value2), std::nullopt, make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("can close and reopen the db")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      store = nullptr;
      store = backend.open(testtmp.path, testtmp.path);

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("overwrites a value and gets it back")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const value2 = "test value 2";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keyValues2 = makeKeyValues({{key, value2}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues2, OnConflict::Replace));

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value2)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("ignores conflicts on a value and gets it back")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const value2 = "test value 2";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keyValues2 = makeKeyValues({{key, value2}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues2, OnConflict::Ignore));

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SECTION("fails to overwrite a value when needed")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const value2 = "test value 2";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keyValues2 = makeKeyValues({{key, value2}});
      TANKER_CHECK_THROWS_WITH_CODE(store->putCacheValues(keyValues2, OnConflict::Fail),
                                    Tanker::DataStore::Errc::ConstraintFailed);

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }
  }

  SECTION("Nuke")
  {
    std::vector<uint8_t> device(128);
    Tanker::Crypto::randomFill(device);
    store->putSerializedDevice(device);

    auto const key = "test key";
    auto const value = "test value";
    auto const keyValues = makeKeyValues({{key, value}});
    store->putCacheValues(keyValues, OnConflict::Fail);

    REQUIRE_NOTHROW(store->nuke());

    // everything is deleted
    CHECK(!store->findSerializedDevice());

    auto const keys = makeKeys({key});
    CacheResult expected{std::nullopt};
    CHECK(store->findCacheValues(keys) == expected);
  }
}
