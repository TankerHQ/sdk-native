#include <Helpers/Entries.hpp>

#include <Tanker/Trustchain/Action.hpp>

namespace Tanker::Trustchain
{
ServerEntry clientToServerEntry(ClientEntry const& e, std::uint64_t index)
{
  return {e.trustchainId(),
          index,
          e.author(),
          Trustchain::Action::deserialize(e.nature(), e.serializedPayload()),
          e.hash(),
          e.signature()};
}

}
