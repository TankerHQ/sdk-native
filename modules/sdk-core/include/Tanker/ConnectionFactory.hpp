#pragma once

#include <Tanker/AConnection.hpp>

namespace Tanker
{
struct ConnectionFactory
{
  [[nodiscard]] static ConnectionPtr create(std::string url);
};
}
