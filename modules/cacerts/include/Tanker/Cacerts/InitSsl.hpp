#pragma once

#if TANKER_BUILD_WITH_SSL
#include <boost/asio/ssl/context.hpp>
#endif

namespace Tanker
{
namespace Cacerts
{
#if TANKER_BUILD_WITH_SSL
boost::asio::ssl::context& get_ssl_context();
#endif
}
}
