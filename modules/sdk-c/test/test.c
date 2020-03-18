#include <ctanker.h>
#include <ctanker/admin.h>
#include <ctanker/identity.h>

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

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

static tanker_options_t make_tanker_options(tanker_app_descriptor_t* app)
{
  tanker_options_t tanker_options = TANKER_OPTIONS_INIT;
  tanker_options.app_id = app->id;
  tanker_options.url = get_config_app_url();
  tanker_options.sdk_type = "test";
  tanker_options.sdk_version = "0.0.1";
  return tanker_options;
}

static void test_sign_up_sign_in(tanker_app_descriptor_t* app)
{
  char const* userId = "alice";

  tanker_options_t options = make_tanker_options(app);
  options.writable_path = "testtmp/test-c";
  #ifdef _WIN32
    _mkdir("testtmp");
    _mkdir("testtmp/test-c");
  #else
    mkdir("testtmp", 0755);
    mkdir("testtmp/test-c", 0755);
  #endif
  tanker_t* tanker = future_get(tanker_create(&options));

  char const* identity =
      future_get(tanker_create_identity(app->id, app->private_key, userId));

  tanker_verification_t verification = TANKER_VERIFICATION_INIT;
  verification.verification_method_type = TANKER_VERIFICATION_METHOD_PASSPHRASE;
  verification.passphrase = "passphrase";

  future_get(tanker_start(tanker, identity));
  future_get(tanker_register_identity(tanker, &verification));
  future_get(tanker_stop(tanker));

  tanker_free_buffer(identity);
  future_get(tanker_destroy(tanker));
}

int main(int argc, char* argv[])
{
  tanker_admin_t* admin = future_get(
      tanker_admin_connect(get_config_app_url(), get_config_id_token()));
  tanker_app_descriptor_t* app =
      future_get(tanker_admin_create_app(admin, "functest"));

  test_sign_up_sign_in(app);

  future_get(tanker_admin_delete_app(admin, app->id));
  tanker_admin_app_descriptor_free(app);
  future_get(tanker_admin_destroy(admin));
}
