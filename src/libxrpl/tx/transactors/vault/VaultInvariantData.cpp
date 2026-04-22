#include <xrpl/tx/transactors/vault/VaultInvariantData.h>
//
#include <xrpl/beast/utility/instrumentation.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Issue.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STNumber.h>

#include <algorithm>

namespace xrpl {

VaultInvariantData::Vault
VaultInvariantData::Vault::make(SLE const& from)
{
    XRPL_ASSERT(from.getType() == ltVAULT, "VaultInvariantData::Vault::make : from Vault object");

    VaultInvariantData::Vault self;
    self.key = from.key();
    self.asset = from.at(sfAsset);
    self.pseudoId = from.getAccountID(sfAccount);
    self.owner = from.at(sfOwner);
    self.shareMPTID = from.getFieldH192(sfShareMPTID);
    self.assetsTotal = from.at(sfAssetsTotal);
    self.assetsAvailable = from.at(sfAssetsAvailable);
    self.assetsMaximum = from.at(sfAssetsMaximum);
    self.lossUnrealized = from.at(sfLossUnrealized);
    return self;
}

VaultInvariantData::Shares
VaultInvariantData::Shares::make(SLE const& from)
{
    XRPL_ASSERT(
        from.getType() == ltMPTOKEN_ISSUANCE,
        "VaultInvariantData::Shares::make : from MPTokenIssuance object");

    VaultInvariantData::Shares self;
    self.share = MPTIssue(makeMptID(from.getFieldU32(sfSequence), from.getAccountID(sfIssuer)));
    self.sharesTotal = from.at(sfOutstandingAmount);
    self.sharesMaximum = from[~sfMaximumAmount].value_or(maxMPTokenAmount);
    return self;
}

[[nodiscard]] VaultInvariantData::DeltaInfo
VaultInvariantData::DeltaInfo::makeDelta(
    Number const& before,
    Number const& after,
    Asset const& asset)
{
    return {
        .delta = after - before,
        .scale = std::max(xrpl::scale(after, asset), xrpl::scale(before, asset))};
}

[[nodiscard]] std::int32_t
VaultInvariantData::computeCoarsestScale(std::vector<DeltaInfo> const& numbers)
{
    if (numbers.empty())
        return 0;

    auto const max = std::ranges::max_element(
        numbers, [](auto const& a, auto const& b) -> bool { return a.scale < b.scale; });
    XRPL_ASSERT_PARTS(
        max->scale,
        "xrpl::VaultInvariantData::computeCoarsestScale",
        "scale set for destinationDelta");
    return max->scale.value_or(STAmount::cMaxOffset);
}

void
VaultInvariantData::visitEntry(bool isDelete, SLE::const_ref before, SLE::const_ref after)
{
    // If `before` is empty, this means an object is being created, in which
    // case `isDelete` must be false. Otherwise `before` and `after` are set and
    // `isDelete` indicates whether an object is being deleted or modified.
    XRPL_ASSERT(
        after != nullptr && (before != nullptr || !isDelete),
        "xrpl::VaultInvariantData::visitEntry : some object is available");

    // Number balanceDelta will capture the difference (delta) between "before"
    // state (zero if created) and "after" state (zero if destroyed), and
    // preserves value scale (exponent) to round values to the same scale during
    // validation. It is used to validate that the change in account balances
    // matches the change in vault balances, stored to deltas_ at the end of
    // this function.
    DeltaInfo balanceDelta{.delta = numZero, .scale = std::nullopt};

    std::int8_t sign = 0;
    if (before)
    {
        switch (before->getType())
        {
            case ltVAULT:
                beforeVault_.push_back(Vault::make(*before));
                break;
            case ltMPTOKEN_ISSUANCE:
                // At this moment we have no way of telling if this object holds
                // vault shares or something else. Save it for finalize.
                beforeMPTs_.push_back(Shares::make(*before));
                balanceDelta.delta =
                    static_cast<std::int64_t>(before->getFieldU64(sfOutstandingAmount));
                // MPTs are ints, so the scale is always 0.
                balanceDelta.scale = 0;
                sign = 1;
                break;
            case ltMPTOKEN:
                balanceDelta.delta = static_cast<std::int64_t>(before->getFieldU64(sfMPTAmount));
                // MPTs are ints, so the scale is always 0.
                balanceDelta.scale = 0;
                sign = -1;
                break;
            case ltACCOUNT_ROOT:
                balanceDelta.delta = before->getFieldAmount(sfBalance);
                // Account balance is XRP, which is an int, so the scale is
                // always 0.
                balanceDelta.scale = 0;
                sign = -1;
                break;
            case ltRIPPLE_STATE: {
                auto const amount = before->getFieldAmount(sfBalance);
                balanceDelta.delta = amount;
                // Trust Line balances are STAmounts, so we can use the exponent
                // directly to get the scale.
                balanceDelta.scale = amount.exponent();
                sign = -1;
                break;
            }
            default:;
        }
    }

    if (!isDelete && after)
    {
        switch (after->getType())
        {
            case ltVAULT:
                afterVault_.push_back(Vault::make(*after));
                break;
            case ltMPTOKEN_ISSUANCE:
                // At this moment we have no way of telling if this object holds
                // vault shares or something else. Save it for finalize.
                afterMPTs_.push_back(Shares::make(*after));
                balanceDelta.delta -=
                    Number(static_cast<std::int64_t>(after->getFieldU64(sfOutstandingAmount)));
                // MPTs are ints, so the scale is always 0.
                balanceDelta.scale = 0;
                sign = 1;
                break;
            case ltMPTOKEN:
                balanceDelta.delta -=
                    Number(static_cast<std::int64_t>(after->getFieldU64(sfMPTAmount)));
                // MPTs are ints, so the scale is always 0.
                balanceDelta.scale = 0;
                sign = -1;
                break;
            case ltACCOUNT_ROOT:
                balanceDelta.delta -= Number(after->getFieldAmount(sfBalance));
                // Account balance is XRP, which is an int, so the scale is
                // always 0.
                balanceDelta.scale = 0;
                sign = -1;
                break;
            case ltRIPPLE_STATE: {
                auto const amount = after->getFieldAmount(sfBalance);
                balanceDelta.delta -= Number(amount);
                // Trust Line balances are STAmounts, so we can use the exponent
                // directly to get the scale.
                if (amount.exponent() > balanceDelta.scale)
                    balanceDelta.scale = amount.exponent();
                sign = -1;
                break;
            }
            default:;
        }
    }

    uint256 const key = (before ? before->key() : after->key());
    // Append to deltas if sign is non-zero, i.e. an object of an interesting
    // type has been updated. A transaction may update an object even when
    // its balance has not changed, e.g. transaction fee equals the amount
    // transferred to the account. We intentionally do not compare balanceDelta
    // against zero, to avoid missing such updates.
    if (sign != 0)
    {
        XRPL_ASSERT_PARTS(
            balanceDelta.scale, "xrpl::VaultInvariantData::visitEntry", "scale initialized");
        balanceDelta.delta *= sign;
        deltas_[key] = balanceDelta;
    }
}

std::optional<VaultInvariantData::DeltaInfo>
VaultInvariantData::deltaAssets(Asset const& vaultAsset, AccountID const& id) const
{
    auto const get =  //
        [&](auto const& it, std::int8_t sign = 1) -> std::optional<DeltaInfo> {
        if (it == deltas_.end())
            return std::nullopt;

        return DeltaInfo{it->second.delta * sign, it->second.scale};
    };

    return std::visit(
        [&]<typename TIss>(TIss const& issue) {
            if constexpr (std::is_same_v<TIss, Issue>)
            {
                if (isXRP(issue))
                    return get(deltas_.find(keylet::account(id).key));
                return get(
                    deltas_.find(keylet::line(id, issue).key), id > issue.getIssuer() ? -1 : 1);
            }
            else if constexpr (std::is_same_v<TIss, MPTIssue>)
            {
                return get(deltas_.find(keylet::mptoken(issue.getMptID(), id).key));
            }
        },
        vaultAsset.value());
}

std::optional<VaultInvariantData::DeltaInfo>
VaultInvariantData::deltaAssetsTxAccount(
    AccountID const& account,
    std::optional<AccountID> const& delegate,
    Asset const& vaultAsset,
    XRPAmount fee) const
{
    auto ret = deltaAssets(vaultAsset, account);
    // Nothing returned or not XRP transaction
    if (!ret.has_value() || !vaultAsset.native())
        return ret;

    // Delegated transaction; no need to compensate for fees
    if (delegate.has_value() && *delegate != account)
        return ret;

    ret->delta += fee.drops();
    if (ret->delta == beast::zero)
        return std::nullopt;

    return ret;
}

std::optional<VaultInvariantData::DeltaInfo>
VaultInvariantData::deltaShares(
    AccountID const& pseudoId,
    uint192 const& shareMPTID,
    AccountID const& id) const
{
    auto const it = [&]() {
        if (id == pseudoId)
            return deltas_.find(keylet::mptIssuance(shareMPTID).key);
        return deltas_.find(keylet::mptoken(shareMPTID, id).key);
    }();

    return it != deltas_.end() ? std::optional<DeltaInfo>(it->second) : std::nullopt;
}

std::optional<VaultInvariantData::Shares>
VaultInvariantData::resolveUpdatedShares(Vault const& afterVault) const
{
    // Find the shares MPTokenIssuance that was modified in the same
    // transaction. Note, we expect afterMPTs_ to be extremely small.
    // For such collections linear search is faster than lookup.
    for (auto const& e : afterMPTs_)
    {
        if (e.share.getMptID() == afterVault.shareMPTID)
            return e;
    }
    return std::nullopt;
}

std::optional<VaultInvariantData::Shares>
VaultInvariantData::resolveBeforeShares(Vault const& beforeVault) const
{
    for (auto const& e : beforeMPTs_)
    {
        if (e.share.getMptID() == beforeVault.shareMPTID)
            return e;
    }
    return std::nullopt;
}

bool
VaultInvariantData::vaultHoldsNoAssets(Vault const& vault)
{
    return vault.assetsAvailable == 0 && vault.assetsTotal == 0;
}

}  // namespace xrpl
