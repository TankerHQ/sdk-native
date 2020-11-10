#include <Tanker/Init.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Init.hpp>

#include <Tanker/AsyncCore.hpp>

#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

namespace Tanker
{
void init()
{
  Crypto::init();
  Cacerts::init();
}

void shutdown()
{
  AsyncCore::stopLogHandlerThreadPool();
  tc::shutdown();
}
}
