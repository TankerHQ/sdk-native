extern "C" {
#include "config.h"
}

#include <Helpers/Config.hpp>

using namespace Tanker;

char const* get_config_app_url()
{
  return TestConstants::trustchainUrl().c_str();
}
char const* get_config_id_token()
{
  return TestConstants::idToken().c_str();
}
