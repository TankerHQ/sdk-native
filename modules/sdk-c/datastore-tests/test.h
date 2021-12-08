#ifndef TANKER_DATASTORE_TEST_H
#define TANKER_DATASTORE_TEST_H

#include <ctanker/datastore.h>

#ifdef __cplusplus
extern "C" {
#endif

int tanker_run_datastore_test(tanker_datastore_options_t* datastore_options,
                              char const* persistent_path,
                              char const* output_path);

#ifdef __cplusplus
}
#endif

#endif
