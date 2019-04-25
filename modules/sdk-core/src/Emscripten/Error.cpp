#include <Tanker/Emscripten/Error.hpp>

#include <Tanker/Emscripten/Helpers.hpp>

#include <Tanker/Error.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>

#include <emscripten/bind.h>

namespace Tanker
{
namespace Emscripten
{
emscripten::val currentExceptionToJs()
{
  try
  {
    throw;
  }
  catch (Tanker::Error::ResourceKeyNotFound const& e)
  {
    auto jerr =
        emscripten::val(EmError{Error::Code::ResourceKeyNotFound, e.what()});
    jerr.set("resourceId", containerToJs(e.resourceId()));
    return jerr;
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

EMSCRIPTEN_BINDINGS(jserrors)
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
}
