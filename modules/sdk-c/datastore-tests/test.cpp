#define CATCH_CONFIG_RUNNER
#include "test.h"

#include <catch2/catch.hpp>

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

int tanker_run_datastore_test(tanker_datastore_options_t* datastore_options,
                              char const* persistent_path,
                              char const* output_path)
{
  datastoreOptions = datastore_options;
  writablePath = persistent_path;

  Catch::Session context;

  if (output_path)
  {
    char const* const opts[] = {"--out", output_path};
    context.applyCommandLine(2, opts);
  }

  return context.run();
}
