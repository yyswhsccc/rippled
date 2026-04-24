#include <xrpl/tx/transactors/vault/VaultWithdraw.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/beast/utility/instrumentation.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/TokenHelpers.h>
#include <xrpl/ledger/helpers/VaultHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STNumber.h>  // IWYU pragma: keep
#include <xrpl/protocol/STTakesAsset.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

namespace xrpl {

NotTEC
VaultWithdraw::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfVaultID] == beast::zero)
    {
        JLOG(ctx.j.debug()) << "VaultWithdraw: zero/empty vault ID.";
        return temMALFORMED;
    }

    if (ctx.tx[sfAmount] <= beast::zero)
        return temBAD_AMOUNT;

    if (auto const destination = ctx.tx[~sfDestination])
    {
        if (*destination == beast::zero)
        {
            return temMALFORMED;
        }
    }

    return tesSUCCESS;
}

TER
VaultWithdraw::preclaim(PreclaimContext const& ctx)
{
    auto const vault = ctx.view.read(keylet::vault(ctx.tx[sfVaultID]));
    if (!vault)
        return tecNO_ENTRY;

    auto const amount = ctx.tx[sfAmount];
    auto const vaultAsset = vault->at(sfAsset);
    auto const vaultShare = vault->at(sfShareMPTID);
    if (amount.asset() != vaultAsset && amount.asset() != vaultShare)
        return tecWRONG_ASSET;

    auto const& vaultAccount = vault->at(sfAccount);
    auto const& account = ctx.tx[sfAccount];
    auto const& dstAcct = ctx.tx[~sfDestination].value_or(account);
    if (auto ter = canTransfer(ctx.view, vaultAsset, vaultAccount, dstAcct); !isTesSuccess(ter))
    {
        JLOG(ctx.j.debug()) << "VaultWithdraw: vault assets are non-transferable.";
        return ter;
    }

    // Enforce valid withdrawal policy
    if (vault->at(sfWithdrawalPolicy) != vaultStrategyFirstComeFirstServe)
    {
        // LCOV_EXCL_START
        JLOG(ctx.j.error()) << "VaultWithdraw: invalid withdrawal policy.";
        return tefINTERNAL;
        // LCOV_EXCL_STOP
    }

    if (ctx.view.rules().enabled(fixSecurity3_1_3) && amount.asset() == vaultShare)
    {
        // Post-fixSecurity3_1_3: if the user specified shares, convert
        // to the equivalent asset amount before checking withdrawal
        // limits. Pre-amendment the limit check was skipped for
        // share-denominated withdrawals.
        auto const sleIssuance = ctx.view.read(keylet::mptIssuance(vaultShare));
        if (!sleIssuance)
        {
            // LCOV_EXCL_START
            JLOG(ctx.j.error()) << "VaultWithdraw: missing issuance of vault shares.";
            return tefINTERNAL;
            // LCOV_EXCL_STOP
        }

        try
        {
            auto const maybeAssets = sharesToAssetsWithdraw(vault, sleIssuance, amount);
            if (!maybeAssets)
                return tefINTERNAL;  // LCOV_EXCL_LINE

            if (auto const ret = canWithdraw(
                    ctx.view,
                    account,
                    dstAcct,
                    *maybeAssets,
                    ctx.tx.isFieldPresent(sfDestinationTag)))
                return ret;
        }
        catch (std::overflow_error const&)
        {
            // It's easy to hit this exception from Number with large enough Scale
            // so we avoid spamming the log and only use debug here.
            JLOG(ctx.j.debug())  //
                << "VaultWithdraw: overflow error with"
                << " scale=" << (int)vault->at(sfScale)  //
                << ", assetsTotal=" << vault->at(sfAssetsTotal)
                << ", sharesTotal=" << sleIssuance->at(sfOutstandingAmount)
                << ", amount=" << amount.value();
            return tecPATH_DRY;
        }
    }
    else
    {
        if (auto const ret = canWithdraw(ctx.view, ctx.tx))
            return ret;
    }

    // If sending to Account (i.e. not a transfer), we will also create (only
    // if authorized) a trust line or MPToken as needed, in doApply().
    // Destination MPToken or trust line must exist if _not_ sending to Account.
    AuthType const authType = account == dstAcct ? AuthType::WeakAuth : AuthType::StrongAuth;
    if (auto const ter = requireAuth(ctx.view, vaultAsset, dstAcct, authType); !isTesSuccess(ter))
        return ter;

    // Cannot withdraw from a Vault an Asset frozen for the destination account
    if (auto const ret = checkFrozen(ctx.view, dstAcct, vaultAsset))
        return ret;

    // Cannot return shares to the vault, if the underlying asset was frozen for
    // the submitter
    if (auto const ret = checkFrozen(ctx.view, account, Asset{vaultShare}))
        return ret;

    return tesSUCCESS;
}

TER
VaultWithdraw::doApply()
{
    auto const vault = view().peek(keylet::vault(ctx_.tx[sfVaultID]));
    if (!vault)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto const mptIssuanceID = *((*vault)[sfShareMPTID]);
    auto const sleIssuance = view().read(keylet::mptIssuance(mptIssuanceID));
    if (!sleIssuance)
    {
        // LCOV_EXCL_START
        JLOG(j_.error()) << "VaultWithdraw: missing issuance of vault shares.";
        return tefINTERNAL;
        // LCOV_EXCL_STOP
    }

    // Note, we intentionally do not check lsfVaultPrivate flag on the Vault. If
    // you have a share in the vault, it means you were at some point authorized
    // to deposit into it, and this means you are also indefinitely authorized
    // to withdraw from it.

    auto const amount = ctx_.tx[sfAmount];
    Asset const vaultAsset = vault->at(sfAsset);

    MPTIssue const share{mptIssuanceID};
    STAmount sharesRedeemed = {share};
    STAmount assetsWithdrawn;
    try
    {
        if (amount.asset() == vaultAsset)
        {
            // Fixed assets, variable shares.
            {
                auto const maybeShares = assetsToSharesWithdraw(vault, sleIssuance, amount);
                if (!maybeShares)
                    return tecINTERNAL;  // LCOV_EXCL_LINE
                sharesRedeemed = *maybeShares;
            }

            if (sharesRedeemed == beast::zero)
                return tecPRECISION_LOSS;
            auto const maybeAssets = sharesToAssetsWithdraw(vault, sleIssuance, sharesRedeemed);
            if (!maybeAssets)
                return tecINTERNAL;  // LCOV_EXCL_LINE
            assetsWithdrawn = *maybeAssets;
        }
        else if (amount.asset() == share)
        {
            // Fixed shares, variable assets.
            sharesRedeemed = amount;
            auto const maybeAssets = sharesToAssetsWithdraw(vault, sleIssuance, sharesRedeemed);
            if (!maybeAssets)
                return tecINTERNAL;  // LCOV_EXCL_LINE
            assetsWithdrawn = *maybeAssets;
        }
        else
        {
            return tefINTERNAL;  // LCOV_EXCL_LINE
        }
    }
    catch (std::overflow_error const&)
    {
        // It's easy to hit this exception from Number with large enough Scale
        // so we avoid spamming the log and only use debug here.
        JLOG(j_.debug())  //
            << "VaultWithdraw: overflow error with"
            << " scale=" << (int)vault->at(sfScale).value()  //
            << ", assetsTotal=" << vault->at(sfAssetsTotal).value()
            << ", sharesTotal=" << sleIssuance->at(sfOutstandingAmount)
            << ", amount=" << amount.value();
        return tecPATH_DRY;
    }

    if (accountHolds(
            view(),
            account_,
            share,
            FreezeHandling::fhZERO_IF_FROZEN,
            AuthHandling::ahIGNORE_AUTH,
            j_) < sharesRedeemed)
    {
        JLOG(j_.debug()) << "VaultWithdraw: account doesn't hold enough shares";
        return tecINSUFFICIENT_FUNDS;
    }

    auto assetsAvailable = vault->at(sfAssetsAvailable);
    auto assetsTotal = vault->at(sfAssetsTotal);
    [[maybe_unused]] auto const lossUnrealized = vault->at(sfLossUnrealized);
    XRPL_ASSERT(
        lossUnrealized <= (assetsTotal - assetsAvailable),
        "xrpl::VaultWithdraw::doApply : loss and assets do balance");

    // The vault must have enough assets on hand. The vault may hold assets
    // that it has already pledged. That is why we look at AssetAvailable
    // instead of the pseudo-account balance.
    if (*assetsAvailable < assetsWithdrawn)
    {
        JLOG(j_.debug()) << "VaultWithdraw: vault doesn't hold enough assets";
        return tecINSUFFICIENT_FUNDS;
    }

    assetsTotal -= assetsWithdrawn;
    assetsAvailable -= assetsWithdrawn;
    view().update(vault);

    auto const& vaultAccount = vault->at(sfAccount);
    // Transfer shares from depositor to vault.
    if (auto const ter =
            accountSend(view(), account_, vaultAccount, sharesRedeemed, j_, WaiveTransferFee::Yes);
        !isTesSuccess(ter))
        return ter;

    // Try to remove MPToken for shares, if the account balance is zero. Vault
    // pseudo-account will never set lsfMPTAuthorized, so we ignore flags.
    // Keep MPToken if holder is the vault owner.
    if (account_ != vault->at(sfOwner))
    {
        if (auto const ter = removeEmptyHolding(view(), account_, sharesRedeemed.asset(), j_);
            isTesSuccess(ter))
        {
            JLOG(j_.debug())  //
                << "VaultWithdraw: removed empty MPToken for vault shares"
                << " MPTID=" << to_string(mptIssuanceID)  //
                << " account=" << toBase58(account_);
        }
        else if (ter != tecHAS_OBLIGATIONS)
        {
            // LCOV_EXCL_START
            JLOG(j_.error())  //
                << "VaultWithdraw: failed to remove MPToken for vault shares"
                << " MPTID=" << to_string(mptIssuanceID)  //
                << " account=" << toBase58(account_)      //
                << " with result: " << transToken(ter);
            return ter;
            // LCOV_EXCL_STOP
        }
        // else quietly ignore, account balance is not zero
    }

    auto const dstAcct = ctx_.tx[~sfDestination].value_or(account_);

    associateAsset(*vault, vaultAsset);

    return doWithdraw(
        view(), ctx_.tx, account_, dstAcct, vaultAccount, preFeeBalance_, assetsWithdrawn, j_);
}

void
VaultWithdraw::visitInvariantEntry(
    bool isDelete,
    std::shared_ptr<SLE const> const& before,
    std::shared_ptr<SLE const> const& after)
{
    invariantData_.visitEntry(isDelete, before, after);
}

bool
VaultWithdraw::finalizeInvariants(
    STTx const& tx,
    TER txResult,
    XRPAmount fee,
    ReadView const& view,
    beast::Journal const& j)
{
    // TODO: Invariants should run for failed transactions too, but skipping
    // here preserves the behaviour from before the refactoring.
    if (!isTesSuccess(txResult))
        return true;

    if (invariantData_.beforeVault().empty() || invariantData_.afterVault().empty())
    {
        JLOG(j.fatal()) <<  //
            "Invariant failed: vault operation succeeded without modifying a vault";
        return false;
    }

    auto result = true;
    auto const& beforeVault = invariantData_.beforeVault()[0];
    auto const& afterVault = invariantData_.afterVault()[0];
    auto const& vaultAsset = afterVault.asset;

    auto const maybeVaultDeltaAssets = invariantData_.deltaAssets(vaultAsset, afterVault.pseudoId);

    if (!maybeVaultDeltaAssets)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal must change vault balance";
        return false;
    }

    // Get the most coarse scale to round calculations to.
    auto const totalDelta = VaultInvariantData::DeltaInfo::makeDelta(
        beforeVault.assetsTotal, afterVault.assetsTotal, vaultAsset);
    auto const availableDelta = VaultInvariantData::DeltaInfo::makeDelta(
        beforeVault.assetsAvailable, afterVault.assetsAvailable, vaultAsset);
    auto const minScale = VaultInvariantData::computeCoarsestScale(
        {*maybeVaultDeltaAssets, totalDelta, availableDelta});

    auto const vaultPseudoDeltaAssets =
        roundToAsset(vaultAsset, maybeVaultDeltaAssets->delta, minScale);

    if (vaultPseudoDeltaAssets >= beast::zero)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal must decrease vault balance";
        result = false;
    }

    // Any payments (including withdrawal) going to the issuer
    // do not change their balance, but destroy funds instead.
    bool const issuerWithdrawal = [&]() -> bool {
        if (vaultAsset.native())
            return false;
        auto const destination = tx[~sfDestination].value_or(tx[sfAccount]);
        return destination == vaultAsset.getIssuer();
    }();

    if (!issuerWithdrawal)
    {
        auto const maybeAccDelta =
            invariantData_.deltaAssetsTxAccount(tx[sfAccount], tx[~sfDelegate], vaultAsset, fee);
        auto const maybeOtherAccDelta = [&]() -> std::optional<VaultInvariantData::DeltaInfo> {
            if (auto const destination = tx[~sfDestination];
                destination && *destination != tx[sfAccount])
                return invariantData_.deltaAssets(vaultAsset, *destination);
            return std::nullopt;
        }();

        if (maybeAccDelta.has_value() == maybeOtherAccDelta.has_value())
        {
            JLOG(j.fatal()) <<  //
                "Invariant failed: withdrawal must change one destination balance";
            return false;
        }

        auto const destinationDelta = maybeAccDelta ? *maybeAccDelta : *maybeOtherAccDelta;

        // The scale of destinationDelta can be coarser than minScale, so we
        // take that into account when rounding.
        auto const localMinScale =
            std::max(minScale, VaultInvariantData::computeCoarsestScale({destinationDelta}));

        auto const roundedDestinationDelta =
            roundToAsset(vaultAsset, destinationDelta.delta, localMinScale);

        if (roundedDestinationDelta <= beast::zero)
        {
            JLOG(j.fatal()) << "Invariant failed: withdrawal must increase destination balance";
            result = false;
        }

        auto const localPseudoDeltaAssets =
            roundToAsset(vaultAsset, vaultPseudoDeltaAssets, localMinScale);
        if (localPseudoDeltaAssets * -1 != roundedDestinationDelta)
        {
            JLOG(j.fatal()) <<  //
                "Invariant failed: withdrawal must change vault and destination balance by equal "
                "amount";
            result = false;
        }
    }

    // We don't need to round shares, they are integral MPT.
    auto const accountDeltaShares =
        invariantData_.deltaShares(afterVault.pseudoId, afterVault.shareMPTID, tx[sfAccount]);
    if (!accountDeltaShares)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal must change depositor shares";
        return false;
    }

    if (accountDeltaShares->delta >= beast::zero)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal must decrease depositor shares";
        result = false;
    }

    auto const vaultDeltaShares =
        invariantData_.deltaShares(afterVault.pseudoId, afterVault.shareMPTID, afterVault.pseudoId);
    if (!vaultDeltaShares || vaultDeltaShares->delta == beast::zero)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal must change vault shares";
        return false;
    }

    if (vaultDeltaShares->delta * -1 != accountDeltaShares->delta)
    {
        JLOG(j.fatal()) <<  //
            "Invariant failed: withdrawal must change depositor and vault shares by equal amount";
        result = false;
    }

    auto const assetTotalDelta =
        roundToAsset(vaultAsset, afterVault.assetsTotal - beforeVault.assetsTotal, minScale);
    // Note, vaultBalance is negative (see check above).
    if (assetTotalDelta != vaultPseudoDeltaAssets)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal and assets outstanding must add up";
        result = false;
    }

    auto const assetAvailableDelta = roundToAsset(
        vaultAsset, afterVault.assetsAvailable - beforeVault.assetsAvailable, minScale);
    if (assetAvailableDelta != vaultPseudoDeltaAssets)
    {
        JLOG(j.fatal()) << "Invariant failed: withdrawal and assets available must add up";
        result = false;
    }

    return result;
}

}  // namespace xrpl
