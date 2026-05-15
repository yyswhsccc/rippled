#include <xrpl/nodestore/detail/DatabaseNodeImp.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Log.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/utility/instrumentation.h>
#include <xrpl/nodestore/Database.h>
#include <xrpl/nodestore/NodeObject.h>
#include <xrpl/nodestore/Scheduler.h>
#include <xrpl/nodestore/Types.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace xrpl::NodeStore {

void
DatabaseNodeImp::store(NodeObjectType type, Blob&& data, uint256 const& hash, std::uint32_t)
{
    storeStats(1, data.size());

    auto obj = NodeObject::createObject(type, std::move(data), hash);
    backend_->store(obj);
    if (cache_)
    {
        // After the store, replace a negative cache entry if there is one
        cache_->canonicalize(hash, obj, [](std::shared_ptr<NodeObject> const& n) {
            return n->getType() == NodeObjectType::Dummy;
        });
    }
}

void
DatabaseNodeImp::asyncFetch(
    uint256 const& hash,
    std::uint32_t ledgerSeq,
    std::function<void(std::shared_ptr<NodeObject> const&)>&& callback)
{
    if (cache_)
    {
        std::shared_ptr<NodeObject> const obj = cache_->fetch(hash);
        if (obj)
        {
            callback(obj->getType() == NodeObjectType::Dummy ? nullptr : obj);
            return;
        }
    }
    Database::asyncFetch(hash, ledgerSeq, std::move(callback));
}

void
DatabaseNodeImp::sweep()
{
    if (cache_)
        cache_->sweep();
}

std::shared_ptr<NodeObject>
DatabaseNodeImp::fetchNodeObject(
    uint256 const& hash,
    std::uint32_t,
    FetchReport& fetchReport,
    bool duplicate)
{
    std::shared_ptr<NodeObject> nodeObject = cache_ ? cache_->fetch(hash) : nullptr;

    if (!nodeObject)
    {
        JLOG(j_.trace()) << "fetchNodeObject " << hash << ": record not "
                         << (cache_ ? "cached" : "found");

        Status status{};

        try
        {
            status = backend_->fetch(hash, &nodeObject);
        }
        catch (std::exception const& e)
        {
            JLOG(j_.fatal()) << "fetchNodeObject " << hash
                             << ": Exception fetching from backend: " << e.what();
            rethrow();
        }

        switch (status)
        {
            case Status::Ok:
                if (cache_)
                {
                    if (nodeObject)
                    {
                        cache_->canonicalizeReplaceClient(hash, nodeObject);
                    }
                    else
                    {
                        auto notFound = NodeObject::createObject(NodeObjectType::Dummy, {}, hash);
                        cache_->canonicalizeReplaceClient(hash, notFound);
                        if (notFound->getType() != NodeObjectType::Dummy)
                            nodeObject = notFound;
                    }
                }
                break;
            case Status::NotFound:
                break;
            case Status::DataCorrupt:
                JLOG(j_.fatal()) << "fetchNodeObject " << hash << ": nodestore data is corrupted";
                break;
            default:
                JLOG(j_.warn()) << "fetchNodeObject " << hash << ": backend returns unknown result "
                                << static_cast<int>(status);
                break;
        }
    }
    else
    {
        JLOG(j_.trace()) << "fetchNodeObject " << hash << ": record found in cache";
        if (nodeObject->getType() == NodeObjectType::Dummy)
            nodeObject.reset();
    }

    if (nodeObject)
        fetchReport.wasFound = true;

    return nodeObject;
}

std::vector<std::shared_ptr<NodeObject>>
DatabaseNodeImp::fetchBatch(std::vector<uint256> const& hashes)
{
    std::vector<std::shared_ptr<NodeObject>> results{hashes.size()};
    using namespace std::chrono;
    auto const before = steady_clock::now();
    std::unordered_map<uint256 const*, size_t> indexMap;
    std::vector<uint256 const*> cacheMisses;
    std::vector<uint256> cacheFetch;
    uint64_t hits = 0;
    uint64_t fetches = 0;
    for (size_t i = 0; i < hashes.size(); ++i)
    {
        auto const& hash = hashes[i];
        // See if the object already exists in the cache
        auto nObj = cache_ ? cache_->fetch(hash) : nullptr;
        ++fetches;
        if (!nObj)
        {
            // Try the database
            indexMap[&hash] = i;
            cacheMisses.push_back(&hash);
            cacheFetch.push_back(hash);
        }
        else
        {
            results[i] = nObj->getType() == NodeObjectType::Dummy ? nullptr : nObj;
            // It was in the cache.
            ++hits;
        }
    }

    JLOG(j_.debug()) << "fetchBatch - cache hits = " << (hashes.size() - cacheMisses.size())
                     << " - cache misses = " << cacheMisses.size();
    auto dbResults = backend_->fetchBatch(cacheFetch).first;

    for (size_t i = 0; i < dbResults.size(); ++i)
    {
        auto nObj = std::move(dbResults[i]);
        size_t index = indexMap[cacheMisses[i]];
        auto const& hash = hashes[index];

        if (nObj)
        {
            // Ensure all threads get the same object
            if (cache_)
                cache_->canonicalizeReplaceClient(hash, nObj);
        }
        else
        {
            JLOG(j_.error()) << "fetchBatch - "
                             << "record not found in db or cache. hash = " << strHex(hash);
            if (cache_)
            {
                auto notFound = NodeObject::createObject(NodeObjectType::Dummy, {}, hash);
                cache_->canonicalizeReplaceClient(hash, notFound);
                if (notFound->getType() != NodeObjectType::Dummy)
                    nObj = std::move(notFound);
            }
        }
        results[index] = std::move(nObj);
    }

    auto fetchDurationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(steady_clock::now() - before).count();
    updateFetchMetrics(fetches, hits, fetchDurationUs);
    return results;
}

}  // namespace xrpl::NodeStore
