#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#include <doctest.h>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <Helpers/Config.hpp>
#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

void runTests(std::string const& config, std::string const& env)
{
  Tanker::init();

  Tanker::TestConstants::setConfig(config, env);

  tc::async_resumable([=]() -> tc::cotask<int> {
    doctest::Context context;

    TC_AWAIT(TrustchainFixture::setUp());
    auto const ret = TC_AWAIT(context.run());
    TC_AWAIT(TrustchainFixture::tearDown());
    TC_RETURN(ret);
  })
      .then([](auto fut) {
        try
        {
          fut.get();
        }
        catch (std::exception& e)
        {
          printf("error: %s\n", e.what());
        }
      });
}

EMSCRIPTEN_BINDINGS(jstestmain)
{
  emscripten::function("runTests", &runTests);
}
