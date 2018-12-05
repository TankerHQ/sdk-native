#include "TestVerifier.hpp"

using namespace Tanker;

Entry toVerifiedEntry(UnverifiedEntry const& entry)
{
  return {entry.index, entry.nature, entry.author, entry.action, entry.hash};
}
