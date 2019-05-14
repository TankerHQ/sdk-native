#include <ctanker.h>
#include <ctanker/identity.h>

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

static void* future_get(tanker_future_t* future)
{
  tanker_future_wait(future);
  if (tanker_future_has_error(future))
  {
    fprintf(stderr, "Error: %s\n", tanker_future_get_error(future)->message);
    exit(1);
  }
  void* ret = tanker_future_get_voidptr(future);
  tanker_future_destroy(future);
  return ret;
}

static tanker_options_t make_tanker_options(
    tanker_trustchain_descriptor_t* trustchain)
{
  tanker_options_t tanker_options = TANKER_OPTIONS_INIT;
  tanker_options.trustchain_id = trustchain->id;
  tanker_options.trustchain_url = get_config_trustchain_url();
  tanker_options.sdk_type = "test";
  tanker_options.sdk_version = "0.0.1";
  return tanker_options;
}

static void test_sign_up_sign_in(tanker_trustchain_descriptor_t* trustchain)
{
  char const* userId = "alice";

  tanker_options_t options = make_tanker_options(trustchain);
  options.writable_path = "testtmp/test-c";
  mkdir("testtmp", 0755);
  mkdir("testtmp/test-c", 0755);
  tanker_t* tanker = future_get(tanker_create(&options));

  char const* identity = future_get(
      tanker_create_identity(trustchain->id, trustchain->private_key, userId));

  tanker_authentication_methods_t authentication_methods =
      TANKER_AUTHENTICATION_METHODS_INIT;
  authentication_methods.password = "password";

  future_get(tanker_sign_up(tanker, identity, &authentication_methods));
  future_get(tanker_stop(tanker));

  future_get(tanker_sign_in(tanker, identity, NULL));
  future_get(tanker_stop(tanker));

  tanker_free_buffer(identity);
  future_get(tanker_destroy(tanker));
}

int main(int argc, char* argv[])
{
  tanker_admin_t* admin = future_get(
      tanker_admin_connect(get_config_trustchain_url(), get_config_id_token()));
  tanker_trustchain_descriptor_t* trustchain =
      future_get(tanker_admin_create_trustchain(admin, "functest"));

  test_sign_up_sign_in(trustchain);

  future_get(tanker_admin_delete_trustchain(admin, trustchain->id));
  tanker_admin_trustchain_descriptor_free(trustchain);
  future_get(tanker_admin_destroy(admin));
}
