#include <Tanker/Emscripten/Helpers.hpp>

#include <Tanker/Error.hpp>

namespace Tanker
{
namespace Emscripten
{
template <typename T>
emscripten::val containerToJs(T const& cont)
{
  using emscripten::val;

  auto const Uint8Array = val::global("Uint8Array");
  val memory = val::module_property("buffer");
  return Uint8Array.new_(
      memory, reinterpret_cast<uintptr_t>(cont.data()), cont.size());
}

std::vector<uint8_t> copyToVector(const emscripten::val& typedArray)
{
  using emscripten::val;

  unsigned int length = typedArray["length"].as<unsigned int>();
  std::vector<uint8_t> vec(length);

  val memory = val::module_property("buffer");
  val memoryView = typedArray["constructor"].new_(
      memory, reinterpret_cast<uintptr_t>(vec.data()), length);

  memoryView.call<void>("set", typedArray);

  return vec;
}

template <typename Sig>
emscripten::val toJsFunctionObject(std::function<Sig> functor)
{
  return emscripten::val(functor)["opcall"].template call<emscripten::val>(
      "bind", emscripten::val(functor));
}

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise)
{
  tc::promise<emscripten::val> cpppromise;
  auto const thenCb = std::function<void(emscripten::val const& val)>(
      [=](emscripten::val const& value) mutable {
        cpppromise.set_value(value);
      });
  auto const catchCb = std::function<void(emscripten::val const&)>(
      [=](emscripten::val const& error) mutable {
        cpppromise.set_exception(
            std::make_exception_ptr(Error::formatEx<std::runtime_error>(
                "some error happened, deal with it: {}",
                error.isNull() ? "null" :
                                 error.isUndefined() ?
                                 "undefined" :
                                 error.call<std::string>("toString") + "\n" +
                                         error["stack"].as<std::string>())));
      });
  jspromise.call<emscripten::val>("then", toJsFunctionObject(thenCb))
      .call<emscripten::val>("catch", toJsFunctionObject(catchCb));
  TC_RETURN(TC_AWAIT(cpppromise.get_future()));
}
}
}

EMSCRIPTEN_BINDINGS(jshelpers)
{
  emscripten::class_<std::function<void(emscripten::val const&)>>(
      "NoargOrMaybeMoreFunction")
      .constructor<>()
      .function("opcall",
                &std::function<void(emscripten::val const&)>::operator());
}
