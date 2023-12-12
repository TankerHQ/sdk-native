#include "test.h"

#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>

#include <Helpers/DataStoreTests.hpp>

#include <ctanker/private/CDataStore.hpp>

namespace
{
std::string_view writablePath;
tanker_datastore_options_t* datastoreOptions;
}

TEST_CASE("DataStore")
{
  CTankerStorageBackend backend(*datastoreOptions);
  runDataStoreTests(backend, writablePath);
}

int tanker_run_datastore_test(tanker_datastore_options_t* datastore_options, char const* persistent_path)
{
  datastoreOptions = datastore_options;
  writablePath = persistent_path;

  Catch::Session context;

#ifdef ANDROID
  char const* const opts[] = {"test", "--out=%debug"};
  context.applyCommandLine(2, opts);
#endif

  return context.run();
}
