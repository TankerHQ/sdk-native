#include <catch2/catch.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/TaskCoalescer.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>

#include <range/v3/view/drop.hpp>

#include <map>

#define DEFER_AWAIT(code)                                               \
  tc::async_resumable(                                                  \
      [&]() ->                                                          \
      typename test_helpers_detail::cotask_type<decltype(code)>::type { \
        TC_RETURN(TC_AWAIT(code));                                      \
      })                                                                \
      .to_shared()

namespace
{
struct Value
{
  int id;

  Value() = default;
  Value(int i) : id{i}
  {
  }
  operator int() const
  {
    return id;
  }
};

using coalescer_type = Tanker::TaskCoalescer<Value>;

using taskIds_type = std::vector<int>;
using result_type = tc::shared_future<std::vector<Value>>;
using taskIdsArgs_type = std::vector<taskIds_type>;

tc::cotask<void> checkReturns(std::vector<result_type> const& results,
                              std::vector<std::vector<int>> const& expected)
{
  for (auto i = 0ul; i < results.size(); i++)
  {
    auto const ids = TC_AWAIT(results[i]) | ranges::to<std::vector<int>>;
    CHECK(ids == expected[i]);
  }
}

void checkCounts(std::map<int, int> const& counts,
                 taskIds_type const& ids,
                 int nbCalls = 1)
{
  for (auto const& id : ids)
  {
    auto const found = counts.find(id);
    CHECK(found != counts.end());
    auto const count = found->second;
    CHECK(count == nbCalls);
  }
}

void unblock(tc::promise<int>& blockedHandler)
{
  blockedHandler.set_value(0);
}

void unblockAll(std::vector<tc::promise<int>>& blockedHandlers)
{
  for (auto& blockedHandler : blockedHandlers)
    unblock(blockedHandler);
}

struct SyncState
{
  std::vector<tc::promise<int>> blockedHandler;
  std::vector<tc::promise<int>> startedHandler;
  int handlerIdx;

  void restart(int nbTask)
  {
    startedHandler.resize(0);
    startedHandler.resize(nbTask);
    handlerIdx = 0;
  };

  tc::cotask<void> syncStart()
  {
    tc::promise<int> sync;
    blockedHandler.emplace_back(sync);

    startedHandler[handlerIdx++].set_value(0);

    TC_AWAIT(sync.get_future().to_shared());
  };

  tc::cotask<void> awaitReady()
  {
    for (auto& started : startedHandler)
      (void)TC_AWAIT(started.get_future());
  }
};
}

TEST_CASE("TaskCoalescer")
{
  coalescer_type coalescer;

  SECTION("forwards task errors")
  {
    taskIds_type ids{0, 1, 2};
    auto alwaysError =
        [](taskIds_type const&) -> tc::cotask<std::vector<Value>> {
      throw formatEx(Tanker::Errors::Errc::InvalidArgument, "an error");
    };
    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(coalescer.run(alwaysError, ids)),
                                  Tanker::Errors::Errc::InvalidArgument);
  }

  SECTION("forwards errors from already in-progress task")
  {
    taskIds_type ids{0, 1, 2};
    SyncState state;
    state.restart(1);

    auto alwaysError =
        [&](taskIds_type const&) -> tc::cotask<std::vector<Value>> {
      TC_AWAIT(state.syncStart());

      throw formatEx(Tanker::Errors::Errc::InvalidArgument, "an error");
    };
    // we don't need to await this one
    DEFER_AWAIT(coalescer.run(alwaysError, ids));

    auto handle = [](taskIds_type const&) -> tc::cotask<std::vector<Value>> {
      std::vector<Value> res;
      CHECK(false);
      TC_RETURN(res);
    };
    auto fromPending = DEFER_AWAIT(coalescer.run(handle, ids));

    AWAIT_VOID(state.awaitReady());
    unblockAll(state.blockedHandler);

    TANKER_CHECK_THROWS_WITH_CODE(AWAIT(fromPending),
                                  Tanker::Errors::Errc::InvalidArgument);
  }

  SECTION("omits unresolved ids from resulting array")
  {
    taskIds_type ids{0, 1, 2};
    auto handle =
        [](taskIds_type const& keys) -> tc::cotask<std::vector<Value>> {
      TC_RETURN(keys | ranges::views::drop(1) | ranges::to<std::vector<Value>>);
    };
    auto result = AWAIT(coalescer.run(handle, ids));
    result_type::value_type expected = {1, 2};
    CHECK(result == expected);
  }

  SECTION("When everything goes well")
  {
    struct TestState : public SyncState
    {
      taskIdsArgs_type handledIds;
      std::map<int, int> counts;

      coalescer_type::task_handler_type handle =
          [&](taskIds_type const& ids) -> tc::cotask<std::vector<Value>> {
        TC_AWAIT(this->syncStart());

        handledIds.push_back(ids);
        for (auto id : ids)
        {
          counts[id]++;
        }

        TC_RETURN(ids | ranges::to<std::vector<Value>>);
      };

      std::vector<result_type> makeFutures(coalescer_type& coalescer,
                                           taskIdsArgs_type const& taskIdsArgs)
      {
        restart(taskIdsArgs.size());

        std::vector<result_type> results;
        for (auto const& taskIds : taskIdsArgs)
          results.emplace_back(DEFER_AWAIT(coalescer.run(handle, taskIds)));

        return results;
      };
    };
    TestState state;

    SECTION("resolves task responses out of order")
    {
      taskIdsArgs_type taskIdsArgs{
          {0},
          {1},
          {2},
      };
      auto results = state.makeFutures(coalescer, taskIdsArgs);

      AWAIT_VOID(state.awaitReady());

      unblock(state.blockedHandler[1]);
      unblock(state.blockedHandler[0]);
      unblock(state.blockedHandler[2]);

      REQUIRE_NOTHROW(AWAIT_VOID(checkReturns(results, taskIdsArgs)));
      taskIdsArgs_type const expected = {{1}, {0}, {2}};
      CHECK(state.handledIds == expected);
    }

    SECTION("calls tasksHandler with missing ids only")
    {
      taskIdsArgs_type taskIdsArgs{
          {1, 2},
          {2, 3},
      };
      auto results = state.makeFutures(coalescer, taskIdsArgs);

      AWAIT_VOID(state.awaitReady());
      unblockAll(state.blockedHandler);

      REQUIRE_NOTHROW(AWAIT_VOID(checkReturns(results, taskIdsArgs)));
      taskIdsArgs_type const expected = {{1, 2}, {3}};
      CHECK(state.handledIds == expected);
    }

    SECTION(
        "does not call the tasksHandler if all tasks from newer runs can be "
        "coalesced")
    {
      taskIds_type ids{1, 2, 3};
      taskIdsArgs_type taskIdsArgs{ids, ids, {3}};
      auto results = state.makeFutures(coalescer, taskIdsArgs);

      // The taskHandler is only called once
      AWAIT(state.startedHandler[0].get_future());
      unblockAll(state.blockedHandler);

      REQUIRE_NOTHROW(AWAIT_VOID(checkReturns(results, taskIdsArgs)));
      taskIdsArgs_type const expected = {ids};
      CHECK(state.handledIds == expected);
      checkCounts(state.counts, {1, 2, 3});
    }

    SECTION(
        "calls tasksHandler with ids again once previous tasks are resolved")
    {
      taskIdsArgs_type taskIdsArgs{
          {1, 2},
          {2, 3},
      };

      // first batch
      auto results = state.makeFutures(coalescer, taskIdsArgs);
      AWAIT_VOID(state.awaitReady());
      unblockAll(state.blockedHandler);

      AWAIT_VOID(checkReturns(results, taskIdsArgs));
      checkCounts(state.counts, {1, 2, 3}, 1);

      // second batch
      results = state.makeFutures(coalescer, taskIdsArgs);
      AWAIT_VOID(state.awaitReady());
      unblockAll(state.blockedHandler);

      AWAIT_VOID(checkReturns(results, taskIdsArgs));
      checkCounts(state.counts, {1, 2, 3}, 2);
    }
  }
}
