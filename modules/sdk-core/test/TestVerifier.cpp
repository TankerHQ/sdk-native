#include "TestVerifier.hpp"

using namespace Tanker;

Entry toVerifiedEntry(Trustchain::ServerEntry const& se)
{
  return {se.index(),
          se.action().nature(),
          se.author(),
          se.action(),
          se.hash()};
}
