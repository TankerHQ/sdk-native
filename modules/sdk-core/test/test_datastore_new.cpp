#include <catch2/catch.hpp>

#include <Helpers/DataStoreTests.hpp>

#include <Tanker/DataStore/Sqlite/Backend.hpp>

TEST_CASE("SQLite DataStore")
{
  Tanker::DataStore::SqliteBackend backend;
  runDataStoreTests(backend, ".");
}
