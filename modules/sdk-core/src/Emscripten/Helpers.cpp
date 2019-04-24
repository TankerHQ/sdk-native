#include <Tanker/Emscripten/Helpers.hpp>

#include <Tanker/Crypto/InvalidKeySize.hpp>
#include <Tanker/Error.hpp>

#include <cppcodec/base64_rfc4648.hpp>

using OneArgFunction = std::function<void(emscripten::val const&)>;
using PromiseCallback = std::function<void(emscripten::val, emscripten::val)>;

namespace Tanker
{
namespace Emscripten
{
std::vector<uint8_t> copyToVector(emscripten::val const& typedArray)
{
  using emscripten::val;

  auto const length = typedArray["length"].as<unsigned int>();
  std::vector<uint8_t> vec(length);

  val memory = val::module_property("buffer");
  val memoryView = typedArray["constructor"].new_(
      memory, reinterpret_cast<uintptr_t>(vec.data()), length);

  memoryView.call<void>("set", typedArray);

  return vec;
}

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise)
{
  tc::promise<emscripten::val> cpppromise;
  auto const thenCb = OneArgFunction([=](emscripten::val const& value) mutable {
    cpppromise.set_value(value);
  });
  auto const catchCb =
      OneArgFunction([=](emscripten::val const& error) mutable {
        std::string errorMsg;
        if (error.isNull())
          errorMsg = "null";
        else if (error.isUndefined())
          errorMsg = "undefined";
        else
          errorMsg = error.call<std::string>("toString") + "\n" +
                     error["stack"].as<std::string>();
        cpppromise.set_exception(std::make_exception_ptr(
            Error::formatEx<std::runtime_error>("JS error: {}", errorMsg)));
      });
  jspromise.call<emscripten::val>("then", toJsFunctionObject(thenCb))
      .call<emscripten::val>("catch", toJsFunctionObject(catchCb));
  TC_RETURN(TC_AWAIT(cpppromise.get_future()));
}

emscripten::val currentExceptionToJs()
{
  try
  {
    throw;
  }
  catch (Crypto::InvalidKeySize const& e)
  {
    return emscripten::val(EmError{Error::Code::InvalidArgument, e.what()});
  }
  catch (cppcodec::parse_error const& e)
  {
    return emscripten::val(
        EmError{Error::Code::InvalidArgument,
                fmt::format(fmt("invalid base64: {:s}"), e.what())});
  }
  catch (cppcodec::invalid_output_length const& e)
  {
    return emscripten::val(
        EmError{Error::Code::InvalidArgument,
                fmt::format(fmt("invalid base64 length: {:s}"), e.what())});
  }
  catch (Tanker::Error::Exception const& e)
  {
    return emscripten::val(EmError{e.code(), e.message()});
  }
  catch (std::exception const& e)
  {
    return emscripten::val(EmError{
        Error::Code::Other, std::string(typeid(e).name()) + ": " + e.what()});
  }
  catch (...)
  {
    return emscripten::val(EmError{Error::Code::Other, "unknown error"});
  }
}
}
}

EMSCRIPTEN_BINDINGS(jshelpers)
{
  emscripten::enum_<Tanker::Error::Code>("ErrorCode")
      .value("NoError", Tanker::Error::Code::NoError)
      .value("Other", Tanker::Error::Code::Other)
      .value("InvalidTankerStatus", Tanker::Error::Code::InvalidTankerStatus)
      .value("ServerError", Tanker::Error::Code::ServerError)
      .value("InvalidArgument", Tanker::Error::Code::InvalidArgument)
      .value("ResourceKeyNotFound", Tanker::Error::Code::ResourceKeyNotFound)
      .value("UserNotFound", Tanker::Error::Code::UserNotFound)
      .value("DecryptFailed", Tanker::Error::Code::DecryptFailed)
      .value("InvalidUnlockKey", Tanker::Error::Code::InvalidUnlockKey)
      .value("InternalError", Tanker::Error::Code::InternalError)
      .value("InvalidUnlockPassword",
             Tanker::Error::Code::InvalidUnlockPassword)
      .value("InvalidVerificationCode",
             Tanker::Error::Code::InvalidVerificationCode)
      .value("UnlockKeyAlreadyExists",
             Tanker::Error::Code::UnlockKeyAlreadyExists)
      .value("MaxVerificationAttemptsReached",
             Tanker::Error::Code::MaxVerificationAttemptsReached)
      .value("InvalidGroupSize", Tanker::Error::Code::InvalidGroupSize)
      .value("RecipientNotFound", Tanker::Error::Code::RecipientNotFound)
      .value("GroupNotFound", Tanker::Error::Code::GroupNotFound)
      .value("DeviceNotFound", Tanker::Error::Code::DeviceNotFound)
      .value("IdentityAlreadyRegistered",
             Tanker::Error::Code::IdentityAlreadyRegistered)
      .value("OperationCanceled", Tanker::Error::Code::OperationCanceled)
      .value("NothingToClaim", Tanker::Error::Code::NothingToClaim);

  static_assert(static_cast<int>(Tanker::Error::Code::Last) == 21,
                "Error code not mapped to emscripten");

  emscripten::value_object<Tanker::Emscripten::EmError>("EmError")
      .field("code", &Tanker::Emscripten::EmError::code)
      .field("message", &Tanker::Emscripten::EmError::message);

  emscripten::class_<OneArgFunction>("NoargOrMaybeMoreFunction")
      .constructor<>()
      .function("opcall", &OneArgFunction::operator());

  emscripten::class_<PromiseCallback>("PromiseCallback")
      .constructor<>()
      .function("opcall", &PromiseCallback::operator());
}
