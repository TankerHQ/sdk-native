extern "C" {
#include "config.h"
}

#include <Helpers/Config.hpp>

using namespace Tanker;

char const* get_config_app_management_token()
{
  return TestConstants::appManagementToken().data();
}

char const* get_config_app_management_url()
{
  return TestConstants::appManagementUrl().data();
}

char const* get_config_app_url()
{
  return TestConstants::appdUrl().data();
}

char const* get_config_environment_name()
{
  return TestConstants::environmentName().data();
}
