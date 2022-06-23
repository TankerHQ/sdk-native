#pragma once

#include <gsl/gsl-lite.hpp>

#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/when.hpp>

#include <range/v3/action/sort.hpp>
#include <range/v3/algorithm/for_each.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/set_algorithm.hpp>
#include <range/v3/view/transform.hpp>

#include <exception>
#include <optional>
#include <vector>

namespace Tanker
{
/**
 * TaskCoalescer allows to share results between identical tasks run
 * concurrently.
 *
 * When calling `run()` with a list of IDs, the coalescer will look if a
 * task is already running for any subset of the given IDs. It will re-use
 * the results from the previous task for the matching IDs and run the task
 * only with the remaining IDs.
 */
template <typename Value>
class TaskCoalescer
{
public:
  using id_type = decltype(std::declval<Value>().id);
  using value_type = std::optional<Value>;
  using task_handler_type = fu2::function<tc::cotask<std::vector<Value>>(
      std::vector<id_type> const&)>;

private:
  using result_type = std::vector<Value>;
  using future_type = tc::shared_future<value_type>;
  using futures_type = std::vector<future_type>;

  struct FutureResults
  {
    futures_type futures;
    std::vector<id_type> newTaskIds;
  };

  struct PromiseWrapper
  {
    tc::promise<value_type> promise;
    future_type future;

    PromiseWrapper() : future(promise.get_future().to_shared())
    {
    }
  };

  boost::container::flat_map<id_type, PromiseWrapper> _running;

public:
  tc::cotask<result_type> run(task_handler_type taskHandler,
                              gsl::span<id_type const> ids)
  {
    auto idFutures = coalesceTasks(ids);

    if (idFutures.newTaskIds.size() > 0)
    {
      TC_AWAIT(lookup(taskHandler, idFutures.newTaskIds));
    }

    TC_RETURN(TC_AWAIT(awaitFutures(idFutures.futures)));
  }

  TaskCoalescer() = default;
  TaskCoalescer(TaskCoalescer const&) = delete;
  TaskCoalescer(TaskCoalescer&&) = delete;
  TaskCoalescer& operator=(TaskCoalescer const&) = delete;
  TaskCoalescer& operator=(TaskCoalescer&&) = delete;

private:
  tc::cotask<void> lookup(task_handler_type taskHandler,
                          std::vector<id_type> const& newTaskIds)
  {
    try
    {
      auto const result = TC_AWAIT(taskHandler(newTaskIds));
      ranges::for_each(result, [&](auto const& value) {
        resolveEntry(value.id, std::make_optional<Value>(value));
      });

      auto const requested =
          newTaskIds | ranges::to<std::vector> | ranges::actions::sort;
      auto const got = result |
                       ranges::views::transform(
                           [&](auto const& value) { return value.id; }) |
                       ranges::to<std::vector> | ranges::actions::sort;
      ranges::for_each(ranges::views::set_difference(requested, got),
                       [&](auto const& id) { resolveEntry(id, std::nullopt); });
    }
    catch (...)
    {
      auto error = std::current_exception();
      ranges::for_each(newTaskIds,
                       [&](auto const& id) { rejectEntry(id, error); });
    }
  };

  void resolveEntry(id_type const& id, value_type value)
  {
    if (auto const it = _running.find(id); it != _running.end())
    {
      it->second.promise.set_value(std::move(value));
      _running.erase(it);
    }
  }

  void rejectEntry(id_type const& id, std::exception_ptr err)
  {
    if (auto const it = _running.find(id); it != _running.end())
    {
      it->second.promise.set_exception(err);
      _running.erase(it);
    }
  }

  FutureResults coalesceTasks(gsl::span<id_type const> taskIds)
  {
    futures_type futures;
    std::vector<id_type> newTaskIds;
    for (auto const& id : taskIds)
    {
      if (auto const it = _running.find(id); it != _running.end())
        futures.emplace_back(it->second.future);
      else
      {
        futures.emplace_back(_running[id].future);
        newTaskIds.emplace_back(id);
      }
    }

    return {
        futures,
        newTaskIds,
    };
  }

  tc::cotask<result_type> awaitFutures(futures_type& futures)
  {
    result_type result;
    for (auto& future : futures)
    {
      auto optKey = TC_AWAIT(future);
      if (optKey)
      {
        result.emplace_back(*optKey);
      }
    }

    TC_RETURN(result);
  }
};
}
