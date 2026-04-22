#pragma once

#include <xrpl/beast/utility/Journal.h>
#include <xrpl/ledger/ReadView.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/tx/transactors/vault/VaultInvariantData.h>

namespace xrpl {

/*
 * @brief Protocol-level vault invariants.
 *
 * These checks apply to every transaction that touches a vault, regardless of
 * transaction type.  Transaction-specific invariants live in each transactor's
 * finalizeInvariants method.
 */
class ValidVault
{
    VaultInvariantData data_;

public:
    using DeltaInfo = VaultInvariantData::DeltaInfo;

    void
    visitEntry(
        bool isDelete,
        std::shared_ptr<SLE const> const& before,
        std::shared_ptr<SLE const> const& after);

    bool
    finalize(STTx const&, TER const, XRPAmount const, ReadView const&, beast::Journal const&);

    [[nodiscard]] static std::int32_t
    computeCoarsestScale(std::vector<DeltaInfo> const& numbers)
    {
        return VaultInvariantData::computeCoarsestScale(numbers);
    }
};

}  // namespace xrpl
