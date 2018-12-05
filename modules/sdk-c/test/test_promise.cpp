#include <tanker/async.h>

#include <doctest.h>

TEST_CASE("tanker_promise")
{
  char aVariable = 0;

  tanker_promise_t* prom = tanker_promise_create();
  tanker_future_t* fut = tanker_promise_get_future(prom);
  tanker_promise_set_value(prom, &aVariable);
  tanker_promise_destroy(prom);

  CHECK(tanker_future_get_voidptr(fut) == &aVariable);

  tanker_future_destroy(fut);
}
