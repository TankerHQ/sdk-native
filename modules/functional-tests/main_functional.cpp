#include <iostream>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

#include "TestNameReporter.hpp"
#include "TestSuite.hpp"
#include <Helpers/Config.hpp>
#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Init.hpp>

#include <catch2/catch_session.hpp>

using namespace std::literals::chrono_literals;
using namespace Tanker::Functional;

int main(int argc, char* argv[])
{
  try
  {
    Tanker::init();

    Tanker::TimeoutTerminate tt(Tanker::TestConstants::maxExecutionTimeout());
    Catch::Session session;

    // We run the tests on a different thread than the default thread to be
    // closer to real use-cases. We can't run them on the main thread because we
    // need coroutines
    tc::thread_pool tp;
    tp.start(1);

    return tc::async_resumable("main_functional",
                               tc::executor(tp),
                               [&]() -> tc::cotask<int> {
                                 TC_AWAIT(TrustchainFixture::setUp());
                                 auto const ret = TC_AWAIT(session.run(argc, argv));
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
