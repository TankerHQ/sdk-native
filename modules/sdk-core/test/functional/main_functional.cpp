#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest.h>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/executor.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <Helpers/Config.hpp>
#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Test/Functional/Trustchain.hpp>

using namespace std::literals::chrono_literals;

int main(int argc, char* argv[])
{
  Tanker::init();

  Tanker::TimeoutTerminate tt(5min);
  doctest::Context context(argc, argv);

  tc::thread_pool tp;
  tp.start(1);

  return tc::async_resumable("main_functional",
                             tc::executor(tp),
                             [&]() -> tc::cotask<int> {
                               auto& trustchain =
                                   Tanker::Test::Trustchain::getInstance();
                               TC_AWAIT(trustchain.init());
                               auto const ret = context.run();
                               TC_AWAIT(trustchain.destroy());
                               TC_RETURN(ret);
                             })
      .get();
}
