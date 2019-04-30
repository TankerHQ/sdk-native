#include "TestVerifier.hpp"

using namespace Tanker;

Entry toVerifiedEntry(Trustchain::ServerEntry const& se)
{
  return {se.index(),
          se.action().nature(),
          se.parentHash(),
          se.action(),
          se.hash()};
}
