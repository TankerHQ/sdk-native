#pragma once

#include <doctest/doctest.h>

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

  SUBCASE("Put and get device")
  {
    SUBCASE("returns nullopt when there is no device")
    {
      CHECK(!store->findSerializedDevice());
    }

    SUBCASE("can put and get a device")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      CHECK(store->findSerializedDevice() == device);
    }

    SUBCASE("can close and reopen the db")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));

      // We need to close the DB before we can reopen it
      store.reset();
      store = backend.open(testtmp.path, testtmp.path);

      CHECK(store->findSerializedDevice() == device);
    }

    SUBCASE("can overwrite and get a device")
    {
      std::vector<uint8_t> device(128);
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      Tanker::Crypto::randomFill(device);
      REQUIRE_NOTHROW(store->putSerializedDevice(device));
      CHECK(store->findSerializedDevice() == device);
    }
  }

  SUBCASE("Put and get cache values")
  {
    SUBCASE("returns nothing if the value is not there")
    {
      auto const key = make_buffer("test key");
      auto const keys = {gsl::make_span(key)};
      std::vector<std::optional<std::vector<uint8_t>>> expected{std::nullopt};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SUBCASE("puts no value at all")
    {
      auto const keyValues = makeKeyValues({});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));
    }

    SUBCASE("puts a value and gets it back")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SUBCASE("puts and gets multiple values at once")
    {
      auto const key = "test key";
      auto const key2 = "test another key";
      auto const value = "test value";
      auto const value2 = "test another value";
      auto const keyValues = makeKeyValues({{key, value}, {key2, value2}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      // invert them, just to check that the order is respected
      auto const keys = makeKeys({key2, key});
      CacheResult expected{make_buffer(value2), make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }

    SUBCASE("can close and reopen the db")
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

    SUBCASE("overwrites a value and gets it back")
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

    SUBCASE("ignores conflicts on a value and gets it back")
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

    SUBCASE("fails to overwrite a value when needed")
    {
      auto const key = "test key";
      auto const value = "test value";
      auto const value2 = "test value 2";
      auto const keyValues = makeKeyValues({{key, value}});
      REQUIRE_NOTHROW(store->putCacheValues(keyValues, OnConflict::Fail));

      auto const keyValues2 = makeKeyValues({{key, value2}});
      TANKER_CHECK_THROWS_WITH_CODE(
          store->putCacheValues(keyValues2, OnConflict::Fail),
          Tanker::DataStore::Errc::ConstraintFailed);

      auto const keys = makeKeys({key});
      CacheResult expected{make_buffer(value)};
      CHECK(store->findCacheValues(keys) == expected);
    }
  }

  SUBCASE("Nuke")
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
