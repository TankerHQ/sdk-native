#pragma once

#include <boost/asio/ssl/context.hpp>

namespace Tanker
{
namespace Cacerts
{
void init();
boost::asio::ssl::context& get_ssl_context();
}
}
