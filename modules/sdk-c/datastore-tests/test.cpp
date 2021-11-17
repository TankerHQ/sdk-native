#define DOCTEST_CONFIG_IMPLEMENT
#include "test.h"

#include <doctest/doctest.h>

#include <Helpers/DataStoreTests.hpp>

#include "CDataStore.hpp"

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
                              char const* writable_path,
                              char const* output_path)
{
  datastoreOptions = datastore_options;
  writablePath = writable_path;

  doctest::Context context;

  if (output_path)
    context.setOption("-out", output_path);

  return context.run();
}
