#include <Tanker/KeyPublishStore.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Log.hpp>

TLOG_CATEGORY(KeyPublishStore);

namespace Tanker
{
KeyPublishStore::KeyPublishStore(DataStore::ADatabase* db) : _db(db)
{
}

tc::cotask<void> KeyPublishStore::put(Trustchain::Actions::KeyPublish const& kp)
{
  TC_AWAIT(_db->putKeyPublishes(gsl::make_span(&kp, 1)));
}

tc::cotask<void> KeyPublishStore::put(
    gsl::span<Trustchain::Actions::KeyPublish const> kps)
{
  for (auto const& kp : kps)
    TINFO("adding key publish {} for {}", kp.nature(), kp.resourceId());

  TC_AWAIT(_db->putKeyPublishes(kps));
}

tc::cotask<nonstd::optional<Trustchain::Actions::KeyPublish>>
KeyPublishStore::find(Trustchain::ResourceId const& resourceId)
{
  TC_RETURN(TC_AWAIT(_db->findKeyPublish(resourceId)));
}
}
