#pragma once

#include <boost/asio/ssl/context.hpp>

namespace Tanker
{
namespace Cacerts
{
boost::asio::ssl::context& get_ssl_context();
}
}
