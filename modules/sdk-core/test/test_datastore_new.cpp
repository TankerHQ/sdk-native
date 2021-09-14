#include <doctest/doctest.h>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/UniquePath.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

using namespace Tanker;
using namespace Tanker::DataStore;

TEST_SUITE_BEGIN("DataStore new");

TEST_CASE("Put and get device")
{
  Tanker::UniquePath testtmp("testtmp");

  SqliteBackend backend;
  auto store = backend.open(testtmp.path, testtmp.path);

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

namespace
{
auto makeKeyValues(
    std::vector<std::pair<std::string_view, std::string_view>> vals)
{
  return vals | ranges::views::transform([](auto const& v) {
           return std::pair{
               gsl::make_span(v.first).template as_span<uint8_t const>(),
               gsl::make_span(v.second).template as_span<uint8_t const>()};
         }) |
         ranges::to<std::vector>;
}

auto makeKeys(std::vector<char const*> keys)
{
  return keys | ranges::views::transform([](char const* v) {
           return gsl::span(v, strlen(v)).as_span<uint8_t const>();
         }) |
         ranges::to<std::vector>;
}

using CacheResult = std::vector<std::optional<std::vector<uint8_t>>>;
}

TEST_CASE("Put and get cache values")
{
  Tanker::UniquePath testtmp("testtmp");

  SqliteBackend backend;
  auto store = backend.open(testtmp.path, testtmp.path);

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

TEST_CASE("Nuke")
{
  Tanker::UniquePath testtmp("testtmp");

  SqliteBackend backend;
  auto store = backend.open(testtmp.path, testtmp.path);

  std::vector<uint8_t> device(128);
  Tanker::Crypto::randomFill(device);
  store->putSerializedDevice(device);

  REQUIRE_NOTHROW(store->nuke());

  // everything is deleted
  CHECK(!store->findSerializedDevice());
}

TEST_SUITE_END();
