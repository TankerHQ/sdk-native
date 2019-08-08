#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest.h>
#include <iostream>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <Helpers/Config.hpp>
#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Test/Functional/TrustchainFixture.hpp>

using namespace std::literals::chrono_literals;

int main(int argc, char* argv[])
{
  try
  {
    Tanker::init();

    Tanker::TimeoutTerminate tt(5min);
    doctest::Context context(argc, argv);

    return tc::async_resumable("main_functional",
                               [&]() -> tc::cotask<int> {
                                 TC_AWAIT(TrustchainFixture::setUp());
                                 auto const ret = TC_AWAIT(context.run());
                                 TC_AWAIT(TrustchainFixture::tearDown());
                                 TC_RETURN(ret);
                               })
        .get();
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;
    throw;
  }
}
