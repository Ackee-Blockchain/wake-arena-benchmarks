# Wake Arena Benchmarks

Benchmark results for [Wake Arena](https://ackee.xyz/wake/arena) — a multi-agent AI audit system for Solidity smart contracts using graph-driven reasoning over Data Dependency and Control Flow graphs.

Full writeup: [Wake Arena: Multi-Agent AI Audit with Graph-Driven Reasoning](https://ackee.xyz/blog/wake-arena-multi-agent-ai-audit-with-graph-driven-reasoning/)

## Audit Competition Benchmark

**Dataset:** 14 protocols from [Code4rena](https://code4rena.com) and [Sherlock](https://audits.sherlock.xyz) audit competitions (same dataset used by [Zellic](https://zellic.io)). All codebases and competition findings are public.

**Metric:** High-severity vulnerabilities detected (confirmed by competition judging).

| Protocol | High-Severity Issues | Wake Arena | Zellic Scanner V12 | EVMBench | Plain GPT-5 | Plain Opus 4.5 |
|---|---:|---:|---:|---:|---:|---:|
| [Basin](https://code4rena.com/reports/2024-07-basin) | 2 | **2** | 2 | 2 | 2 | 2 |
| [Blackhole](https://code4rena.com/audits/2025-05-blackhole) | 2 | **2** | 2 | 0 | 1 | 0 |
| [Burve](https://audits.sherlock.xyz/contests/858) | 9 | **2** | 2 | 2 | 2 | 0 |
| [Crestal](https://audits.sherlock.xyz/contests/755) | 1 | **1** | 1 | 1 | 1 | 1 |
| [DODO](https://audits.sherlock.xyz/contests/991) | 5 | **2** | 2 | 2 | 1 | 4 |
| [Lambo.win](https://code4rena.com/audits/2024-12-lambowin) | 4 | **2** | 2 | 1 | 2 | 1 |
| [Lend](https://audits.sherlock.xyz/contests/908) | 28 | **13** | 10 | 4 | 4 | 6 |
| [Mellow](https://audits.sherlock.xyz/contests/964) | 6 | **2** | 2 | 1 | 1 | 0 |
| [Munchables](https://code4rena.com/reports/2024-07-munchables) | 5 | **4** | 4 | 3 | 2 | 3 |
| [Notional Exponent](https://audits.sherlock.xyz/contests/1001) | 11 | **2** | 2 | 1 | 0 | 0 |
| [Phi](https://code4rena.com/reports/2024-08-phi) | 7 | **4** | 6 | 2 | 3 | 3 |
| [Superfluid](https://audits.sherlock.xyz/contests/968) | 2 | **1** | 1 | 1 | 1 | 0 |
| [TraitForge](https://code4rena.com/audits/2024-07-traitforge) | 6 | **2** | 1 | 1 | 2 | 0 |
| [Virtuals](https://code4rena.com/audits/2025-04-virtuals-protocol) | 6 | **4** | 4 | 1 | 2 | 1 |
| **Total** | **94** | **43 (45.7%)** | **41 (43.6%)** | **22 (22.3%)** | **24 (25.5%)** | **21 (22.3%)** |

### Test conditions

- Plain GPT-5 was run via the Code CLI with prompt `"perform extensive deep Solidity smart contract security analysis"` from the repository root. No special guidance.
- Plain Opus 4.5 was run via the Claude Code CLI with the same prompt and conditions.
- Wake Arena scans ran with standard configuration. No per-protocol tuning.
- EVMBench was run using Codex-GPT-5.2 on web and using Codex-GPT-5.2-xhigh locally (both to the same results)
- Testing conducted November 2025.

## Production Audit Results

Wake Arena was integrated into [Ackee Blockchain](https://ackee.xyz)'s manual audit workflow during November 2025 for three production protocols. Unlike benchmark environments, production audits cover the full severity spectrum (Critical through Informational) on interconnected, real-world contracts.

| Client | Project | Delivery | Audit Duration | AI / Total Findings | Critical | High | Medium | Low | Warning | Info |
|---|---|---|---:|---|---|---|---|---|---|---|
| [Lido](https://github.com/Ackee-Blockchain/public-audit-reports/blob/master/2025/ackee-blockchain-lido-stonks-2.0-report.pdf) | Stonks 2.0 | Dec 2, 2025 | 15 days | 4 / 17 | 0/0 | 0/0 | 1/1 | 1/2 | 1/5 | 1/9 |
| [Everstake](https://github.com/Ackee-Blockchain/public-audit-reports/blob/master/2025/ackee-blockchain-everstake-eth2-batch-deposit-report.pdf) | ETH2 Batch Deposit | Nov 14, 2025 | 2 days | 1 / 2 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 1/2 |
| [Printr](https://github.com/Ackee-Blockchain/public-audit-reports/blob/master/2025/ackee-blockchain-printr-protocol-report.pdf) | Protocol | Oct 1, 2025 | 32 days | 21 / 60 | 5/10 | 0/4 | 1/5 | 4/10 | 4/15 | 7/16 |
| **Total** | | | | **26 / 79** | **5/10** | **0/4** | **2/6** | **5/12** | **5/20** | **9/27** |

Wake Arena identified **33% of all findings** and **50% of critical findings** across production audits. In the Printr audit specifically, it discovered **5 critical vulnerabilities and 5 unique findings** beyond those found by human auditors.

LUKSO served as a design partner during development. In a purely AI-driven audit, Wake Arena identified 10 findings (2 High, 6 Medium, 1 Low, 1 Warning) with only 2 false positives.

### Aggregate metrics

| Metric | Value |
|---|---|
| True positive rate | > 50% |
| False positive rate | < 50% |
| Share of all reported findings | 33% |
| Share of critical findings | 50% |

---

## Per-Protocol Findings

Detailed descriptions of every high-severity vulnerability detected by Wake Arena across the benchmark dataset. All findings were discovered independently — no special prompting, no human assistance. Each scan ran the full pipeline: compilation, graph analysis, multi-agent reasoning, report generation.

### Basin (Code4rena, July 2024) — 2/2

<details>
<summary><b>[H-01]</b> Missing owner/role gating on upgrade endpoints enables permissionless upgrades</summary>

`upgradeTo` and `upgradeToAndCall` rely solely on `_authorizeUpgrade` for gating, which enforces only environmental checks (delegatecall context, Aquifer mapping, UUPS `proxiableUUID`) but does not restrict the caller by owner or role. Any external caller can invoke upgrade endpoints and change the implementation to any candidate satisfying environment checks, bypassing governance.
</details>

<details>
<summary><b>[H-02]</b> <code>decodeWellData</code> checks <code>decimal0</code> twice, leaving <code>decimal1</code> at 0 and mis-scaling token1</summary>

`decodeWellData` uses the same sentinel check twice for `decimal0` and never checks `decimal1` before defaulting to 18. When `decimal1` is encoded as 0 to signal "default to 18", it remains 0. Downstream scaling in `getScaledReserves` multiplies token 1 by `10 ** (18 - 0) = 10 ** 18`, mis-scaling reserves and corrupting pricing, reserve solves, and rate calculations.
</details>

### Blackhole (Code4rena, May 2025) — 2/2

<details>
<summary><b>[H-01]</b> <code>setRouter</code> inverts the zero-address check, only allowing <code>router = address(0)</code></summary>

`setRouter` inverts the zero-address guard, requiring the new router to be the zero address (`require(_router == address(0), "ZA")`). This prevents the owner from configuring any valid router. Calls such as `IGenesisPool(_genesisPool).launch(router, MATURITY_TIME)` will use an invalid address, causing failures.
</details>

<details>
<summary><b>[H-02]</b> <code>createGauge</code> permits untrusted <code>_algebraEternalFarming</code>, enabling theft of factory-held reward tokens</summary>

`createGauge` is externally callable without modifiers and accepts caller-supplied `farmingParam.algebraEternalFarming`. It forwards this to `createEternalFarming`, which unconditionally grants an ERC20 approval of `1e10` to the user-supplied `_algebraEternalFarming` before making an external call to it. Because the address is not validated against a trusted registry, any actor can point it to an arbitrary contract they control, pulling tokens from the factory via `transferFrom`.
</details>

### Burve (Sherlock, April 2025) — 2/9

<details>
<summary><b>[H-03]</b> Incorrect netting in <code>commit</code> drops deposits when withdrawals exceed deposits</summary>

The commit netting branch incorrectly zeros `assetsToDeposit` before subtracting it from `assetsToWithdraw` when `assetsToWithdraw > assetsToDeposit`. No netting occurs: the full withdrawal executes while the pending deposit is dropped. Because deposit and withdraw already mutate internal share accounting assuming netting will occur, this creates unbacked shares and persistent accounting mismatch.
</details>

<details>
<summary><b>[H-06]</b> Uninitialized return variable used as tax base in <code>removeValueSingle</code> enables zero-fee withdrawals</summary>

`removeValueSingle` computes `realTax` from the return variable `removedBalance` before that variable is assigned. Since return variables are zero-initialized in Solidity, `removedBalance` equals 0 at multiplication time, so `realTax` is always 0. Users withdraw the full gross amount without paying tax, the protocol accrues no earnings, and the `minReceive` slippage guard evaluates against the gross amount instead of net-of-tax.
</details>

### Crestal (Sherlock, March 2025) — 1/1

<details>
<summary><b>[H-01]</b> Unauthenticated allowance drain via public <code>payWithERC20</code></summary>

`payWithERC20` in the `Payment` contract is public and accepts arbitrary `fromAddress` and `toAddress`. It invokes `token.safeTransferFrom(fromAddress, toAddress, amount)` without authenticating the caller, binding `fromAddress` to `msg.sender`, or validating any signed authorization. Any user can trigger spending of any allowance that `fromAddress` has granted to this contract and redirect funds to an arbitrary `toAddress`.
</details>

### DODO Cross-Chain DEX (Sherlock, June 2025) — 2/5

<details>
<summary><b>[H-04]</b> Unbound <code>params.fromToken</code> in <code>withdrawToNativeChain</code> enables arbitrary token draining via DODO mixSwap</summary>

Unbound `params.fromToken` in `withdrawToNativeChain` allows the contract to approve and spend arbitrary tokens it holds through `DODOApprove` when executing `_doMixSwap`. The approval amount is derived from caller-supplied `amount`, while the token to approve is taken from caller-supplied `params.fromToken`. Since `params.fromToken` is not enforced to equal the `zrc20` that was transferred in, any contract-held balance can be drained.
</details>

<details>
<summary><b>[H-05]</b> Non-EVM refund theft via authorization bypass in <code>claimRefund</code></summary>

The authorization in `claimRefund` is incorrectly bound to `msg.sender` for non-EVM refunds. For refunds where `refundInfo.walletAddress.length != 20`, the code sets `receiver = msg.sender` and then checks `require(bots[msg.sender] || msg.sender == receiver)`. Because `receiver` equals `msg.sender` by construction, the require always passes for any caller, enabling any address to claim non-EVM refunds.
</details>

### Lambo.win (Code4rena, December 2024) — 2/4

<details>
<summary><b>[H-01]</b> ERC20-mode <code>cashIn</code> mints by <code>msg.value</code>, enabling unbacked minting and zero-credit deposits</summary>

`cashIn` mints virtual tokens based on `msg.value` even when the underlying asset is an ERC20 token. In the ERC20 branch, the function transfers `amount` ERC20 tokens from the caller but mints `msg.value` virtual tokens. Users depositing ERC20 with `msg.value == 0` receive 0 virtual tokens while their ERC20 is locked. Attackers can send ETH with `amount == 0` to receive unbacked virtual tokens they can `cashOut` to drain others' ERC20 deposits.
</details>

<details>
<summary><b>[H-02]</b> Front-run DoS by pre-creating Uniswap pair (<code>PAIR_EXISTS</code>) due to predictable next clone address</summary>

`createLaunchPad` deploys a new quote token clone using `Clones.clone` (via CREATE), then immediately calls Uniswap V2 `createPair`. Because CREATE-based addresses are derived from the factory's address and its nonce, an observer can predict the next clone address. An attacker can front-run and pre-create the pair for `(virtualLiquidityToken, predictedQuoteToken)`, causing the victim's `createLaunchPad` to revert with `PAIR_EXISTS`.
</details>

### Lend (Sherlock, June 2025) — 13/28

<details>
<summary><b>[H-01]</b> <code>claimLend</code> fails to decrement <code>lendAccrued</code> after grant, allowing repeated reward claims and LEND drain</summary>

`claimLend` transfers accrued LEND but never reduces the recorded accrual in storage. After a successful transfer, `lendAccrued(account)` remains unchanged, allowing the same accrual to be claimed repeatedly whenever the router holds enough LEND.
</details>

<details>
<summary><b>[H-03]</b> <code>borrowWithInterest</code> reverts for legitimate multi-direction positions (both arrays populated)</summary>

`borrowWithInterest` enforces that only one of `crossChainBorrows` or `crossChainCollaterals` is populated for a given user and underlying on a chain. This invariant does not hold for legitimate multi-direction positions involving the same underlying in opposite directions across different remote chains, causing DoS in repay and accounting flows.
</details>

<details>
<summary><b>[H-04]</b> Collateral seized before repayment; <code>LiquidationSuccess</code> uses foreign lToken, bricking cross-chain liquidation</summary>

Collateral is seized on the collateral chain before repayment is secured, and the follow-up `LiquidationSuccess` handler repays using a foreign `lToken` address. On the debt chain, `liquidateCrossChain` computes seize tokens and sends `CrossChainLiquidationExecute` without first escrowing or pulling repayment funds from the liquidator. On the collateral chain, `_handleLiquidationExecute` immediately updates accounting and reduces the borrower's collateral before any guarantee that repayment will succeed, permanently desynchronizing borrower state across chains.
</details>

<details>
<summary><b>[H-07]</b> Redeem underpays by using pre-accrual <code>exchangeRateStored</code>; surplus underlying stranded in router</summary>

`redeem` computes `expectedUnderlying` using `exchangeRateStored` read before calling the market's `redeem`. The `redeem` call accrues interest and uses the post-accrual rate, so the router receives more underlying than it forwards to the user. The difference remains stuck in the router and accumulates over time.
</details>

<details>
<summary><b>[H-08]</b> <code>borrowWithInterest</code> excludes destination-chain collaterals, zeroing cross-chain debt and blocking liquidation</summary>

`borrowWithInterest` fails to include cross-chain debt on destination chains because the collaterals branch erroneously requires both `destEid == currentEid` and `srcEid == currentEid`. On genuine cross-chain borrows originating on Chain A with debt on Chain B, `destEid == currentEid` but `srcEid != currentEid`, so the condition is always false. This incorrect zero balance corrupts liquidity calculations and liquidation limits.
</details>

<details>
<summary><b>[H-09]</b> Supply credits lTokens using stale <code>exchangeRateStored</code>, causing accounting drift and redeem DoS</summary>

Supply uses `exchangeRateStored` from before mint and credits `mintTokens` using the stale rate. The subsequent mint call accrues interest and uses the post-accrual exchange rate, so actual lTokens minted to the router are fewer than the credited amount. This creates persistent accounting surplus that eventually causes redemption reverts.
</details>

<details>
<summary><b>[H-10]</b> Non-atomic cross-chain liquidation seizes collateral before collecting repayment, enabling unpaid seizures</summary>

The liquidation protocol seizes collateral on the collateral chain first, then attempts to collect repayment from the liquidator on the debt chain. There is no escrow of the liquidator's tokens prior to seizure, so if the liquidator cannot or will not pay, repayment fails while collateral has already been redistributed.
</details>

<details>
<summary><b>[H-18]</b> Cross-chain debt undercount and repay DoS on destination chain in <code>borrowWithInterest</code></summary>

Cross-chain debt becomes invisible on the destination chain because the `borrowWithInterest` collaterals branch uses an unsatisfiable predicate requiring both `destEid` and `srcEid` to equal `currentEid`. This causes under-accounting of debt in helpers like `getHypotheticalAccountLiquidityCollateral` and repay-path DoS where `CoreRouter.repayBorrowInternal` requires `borrowedAmount > 0` but `borrowWithInterest` incorrectly returns 0.
</details>

<details>
<summary><b>[H-19]</b> Liquidation repayment uses collateral <code>seizeTokens</code> instead of <code>repayAmount</code></summary>

After seizing collateral, the `LiquidationSuccess` handler repays the borrower using `payload.amount`, but that field was set to `seizeTokens` (collateral lToken units) during `_executeLiquidationCore`. Repayment must use `repayAmount` in the borrowed asset's underlying units, causing incorrect debt settlement.
</details>

<details>
<summary><b>[H-21]</b> Stale source-chain collateral snapshot enables undercollateralized cross-chain borrowing</summary>

The destination-chain borrow handler trusts a collateral value snapshotted on the source chain at send time. There is no lock on source-chain collateral while the message is in flight. The borrower can withdraw source-chain collateral after initiating cross-chain borrow but before destination execution, allowing undercollateralized or uncollateralized borrowing.
</details>

<details>
<summary><b>[H-22]</b> Liquidation validity check uses wrong units and wrong action model, enabling seizure of healthy accounts</summary>

`_checkLiquidationValid` models an additional borrow in the collateral market and passes `payload.amount` as `borrowAmount`. In this flow, `payload.amount` is the number of lTokens to seize, not underlying-denominated borrow amount. This mixes units and incorrectly inflates the "borrowed" side of the solvency check, enabling liquidation of healthy accounts.
</details>

<details>
<summary><b>[H-25]</b> <code>LiquidationSuccess</code> uses foreign lToken and wrong EIDs; repayment never executes after collateral seized</summary>

After seizing collateral on the collateral chain, the router sends a `LiquidationSuccess` message back to the debt chain. The receiving handler `_handleLiquidationSuccess` attempts to look up the borrow position and repay the debt using the collateral-chain `destlToken` and mismatched endpoint IDs. This causes the handler to fail to locate the record or revert when interacting with an unknown lToken, leaving repayment unexecuted while collateral has already been seized.
</details>

<details>
<summary><b>[H-27]</b> First-time borrowers bypass per-user collateral checks due to zero <code>borrowIndex</code> path</summary>

In `borrow`, the contract computes borrowed and collateral including the new amount, but then derives `borrowAmount` as zero when `currentBorrow.borrowIndex == 0` (first-time borrowers). The per-user collateral check `collateral >= borrowAmount` becomes `collateral >= 0`, always passing and enabling new users to borrow against other users' collateral held by the router.
</details>

### Mellow (Sherlock, July 2025) — 2/6

<details>
<summary><b>[H-01]</b> Threshold bypass: duplicate signer entries counted as distinct in <code>checkSignatures</code></summary>

The Consensus multisig validator counts provided signatures against threshold but does not enforce that each signature is produced by a unique signer. The same signer can be repeated in the signatures array to satisfy any threshold, degrading a k-of-N policy to effectively 1-of-N as long as one registered signer is willing or compromised.
</details>

<details>
<summary><b>[H-04]</b> Protocol fee double-accrual across non-base-asset reports because timestamp is only updated for base asset</summary>

A protocol-fee accrual checkpoint is stored per vault in `timestamps`. `calculateFee` unconditionally adds time-based protocol fees proportional to `block.timestamp - timestamps[vault]` for any asset, while `updateState` advances the checkpoint only when `asset == baseAsset[vault]` and returns early otherwise. The same elapsed period is charged multiple times across different non-base-asset reports until a base-asset report finally updates the timestamp, systematically over-minting protocol fee shares.
</details>

### Munchables (Code4rena, July 2024) — 4/5

<details>
<summary><b>[H-01]</b> Missing <code>plotId</code> update on transfer causes stuck occupancy and event inconsistency</summary>

`transferToUnoccupiedPlot` updates occupancy bitmaps for old and new plots but never updates the staked token's `toilerState.plotId` field. The contract retains a stale plot id in storage while `plotOccupied` reflects the new plot. When the renter calls `unstakeMunchable`, the function frees the old plot id (already empty), leaving the new plot permanently marked as occupied.
</details>

<details>
<summary><b>[H-02]</b> Off-by-one in invalid-plot check allows farming on removed plots</summary>

The invalid plot detection in `_farmPlots` uses `_getNumPlots(landlord) < _toiler.plotId` instead of `>=`, missing the equality case. When a landlord reduces the number of plots, a toiler whose `plotId` equals the new plot count should be marked invalid but isn't. Staked tokens on the highest removed index continue farming, causing accounting errors.
</details>

<details>
<summary><b>[H-04]</b> Time-delta underflow in <code>_farmPlots</code> when using landlord <code>lastUpdated</code> on invalid plot causes revert, blocking user actions</summary>

When a staked token's `plotId` exceeds the landlord's available plots, `_farmPlots` substitutes `timestamp = plotMetadata[landlord].lastUpdated` and computes the farming delta as `timestamp - _toiler.lastToilDate`. If `lastUpdated` is zero or earlier than `lastToilDate`, the subtraction underflows under Solidity 0.8 and reverts. Because `_farmPlots` is executed by the `forceFarmPlots` modifier on `stakeMunchable`, `unstakeMunchable`, and `transferToUnoccupiedPlot`, this locks assets until metadata is updated.
</details>

<details>
<summary><b>[H-05]</b> Dirty flag in <code>_farmPlots</code> is never cleared, permanently disabling farming for affected tokens</summary>

When a staked token's `plotId` is no longer valid, `_farmPlots` sets `toilerState[tokenId].dirty = true` for a one-time adjustment. On subsequent calls, `if (_toiler.dirty) continue;` skips farming entirely. No code path clears the dirty flag, including `transferToUnoccupiedPlot`, so the token never accrues schnibbles again unless the owner fully unstakes and restakes.
</details>

### Notional Exponent (Sherlock, July 2025) — 2/11

<details>
<summary><b>[H-03]</b> Off-by-one in batch range includes previous <code>batchId</code>, enabling cross-request asset misattribution</summary>

`_finalizeWithdrawImpl` and `canFinalizeWithdrawRequest` iterate from `initialBatchId` to `finalBatchId` inclusive. However, `initialBatchId` is captured before `initiateRedemption` and `finalBatchId` after; if `batchId` increments during initiation, the upxETH for the current request lies in `(initialBatchId + 1 .. finalBatchId)`. Including `initialBatchId` sweeps balances from the prior batch, causing the current request to redeem upxETH belonging to an earlier request.
</details>

<details>
<summary><b>[H-06]</b> Withdrawal initiation DoS after ~65k requests due to 16-bit nonce overflow in <code>s_batchNonce</code></summary>

The withdraw request identifier packs a 16-bit `s_batchNonce` in the high bits and uses `++s_batchNonce` during initiation. In Solidity 0.8+, arithmetic on `uint16` is checked; once the counter reaches 65535, the next increment reverts, permanently denying further withdrawal initiation.
</details>

### Phi (Code4rena, October 2024) — 4/7

<details>
<summary><b>[H-01]</b> Art creation signature lacks domain separation, enabling cross-chain replay</summary>

The `createArt` authorization verifies a personal-signature over `(uint256 expiresIn, string uri, bytes credData)` without binding to `block.chainid` or `address(this)`. A valid art-creation signature for Chain A can be replayed on Chain B if the same `phiSignerAddress` is configured, creating unintended duplicate art across chains and bypassing per-chain rollout policies.
</details>

<details>
<summary><b>[H-02]</b> <code>createArt</code> signatures do not bind <code>CreateConfig</code>, allowing parameter hijack and revenue redirection</summary>

The factory signature only covers `(expiresIn, uri, credData)` and does not bind `CreateConfig` fields or the caller. Any party with a valid signed payload can front-run `createArt` with arbitrary `artist`, `receiver`, `mintFee`, and timing parameters. The attacker gains persistent control via `onlyArtCreator` and redirects revenue. The first creation also fixes the per-cred ERC1155 contract address permanently.
</details>

<details>
<summary><b>[H-05a]</b> Public <code>_addCredIdPerAddress</code> allows arbitrary mutation of per-user position metadata (griefing/DoS)</summary>

`_addCredIdPerAddress` is declared public with no access control and accepts an arbitrary `sender_` address. Any external caller can append arbitrary `credId_` values into another account's `_credIdsPerAddress` array and overwrite its stored index mapping. An attacker can bloat a victim's positions array with duplicate or nonexistent entries, skew the index mapping, and degrade pagination.
</details>

<details>
<summary><b>[H-05b]</b> Public <code>_removeCredIdPerAddress</code> enables unauthorized deletion and sell-to-zero DoS</summary>

`_removeCredIdPerAddress` is declared public with no access control. Any external caller can remove any `credId` from any address's positions array, desynchronizing `_credIdsPerAddress` with its index mappings. When the legitimate user later sells to zero, the contract reverts due to mismatched indices, permanently blocking sell-to-zero for that position.
</details>

### Superfluid (Sherlock, June 2025) — 1/2

<details>
<summary><b>[H-01]</b> <code>provideLiquidity</code> can spend staked tokens (no available-balance check), causing double counting and accounting breakage</summary>

`provideLiquidity` does not enforce that `supAmount` is bounded by the locker's available (non-staked) balance. Staking only updates internal `_stakedBalance` while tokens remain in the contract's address, so Uniswap's position manager can pull staked tokens when minting an LP position. This violates the invariant `FLUID.balanceOf(this) >= _stakedBalance`, enables double counting, and can break accounting and unlock flows.
</details>

### TraitForge (Code4rena, July 2024) — 2/6

<details>
<summary><b>[H-01]</b> Batch mint loop uses global <code>_tokenIds</code>, blocking <code>mintWithBudget</code> after generation-1 cap</summary>

The `mintWithBudget` while-condition compares the global token counter `_tokenIds` against per-generation limit `maxTokensPerGen`. Because `_tokenIds` is monotonically increasing across all generations, after the first generation mints `maxTokensPerGen` tokens, the condition `_tokenIds < maxTokensPerGen` becomes false forever, preventing any further batch mints in subsequent generations.
</details>

<details>
<summary><b>[H-02]</b> Burn before airdrop start lets current holder reduce the initial minter's airdrop allocation</summary>

In `burn(uint256 tokenId)`, while the airdrop has not started, the contract subtracts entropy from `initialOwners[tokenId]`. `initialOwners` is set at mint time and never updated on transfer. Any current holder or approved operator can burn the token before airdrop starts and force a deduction from the original minter's airdrop allocation.
</details>

### Virtuals (Code4rena, April 2025) — 4/6

<details>
<summary><b>[H-01]</b> Permissionless validator registration enables sybil set inflation, base score manipulation, and gas-based DoS</summary>

`addValidator` is publicly callable and lacks access control, allowing any account to register an arbitrary validator for any `virtualId`. `_addValidator` and `_initValidatorScore` append to the per-virtual validator array and assign a non-zero base score tied to the DAO's proposal count. This enables sybil inflation, upward manipulation of aggregated validator scoring, and unbounded growth of the `_validators[virtualId]` array with realistic out-of-gas reverts in downstream flows.
</details>

<details>
<summary><b>[H-03]</b> Unbound <code>virtualId</code> in <code>updateImpact</code> enables cross-persona impact and dataset score manipulation</summary>

`updateImpact` accepts caller-controlled `virtualId` and `proposalId` and computes the baseline service using `_coreServices[virtualId][_cores[proposalId]]`, with no binding between the two. Any caller can pair a victim `proposalId` with an unrelated `virtualId` to compare maturity against the wrong persona's last service or against zero, directly changing `_impacts[proposalId]` and corrupting dataset scoring when the proposal has an associated dataset.
</details>

<details>
<summary><b>[H-04]</b> Unchecked <code>parentId</code> enables cross-DAO lineage forgery and unbounded children growth</summary>

The mint function accepts an arbitrary `parentId` and only enforces `parentId != proposalId`, then writes the linkage and appends to the parent's children without validating that the parent exists, belongs to the same virtual persona, or that the caller is authorized. This allows cross-DAO ancestry forgery, attachment of children to nonexistent parents, and unbounded bloating of `_children[parentId]` for griefing.
</details>

<details>
<summary><b>[H-06]</b> <code>promptMulti</code> can transfer to zero address or stale TBA because <code>prevAgentId</code> is never updated</summary>

The `promptMulti` loop initializes `prevAgentId` to 0 and `agentTba` to `address(0)` but never updates `prevAgentId` inside the loop. The refresh condition `if (prevAgentId != agentId)` fails when `agentId == 0`, leaving `agentTba` unchanged. For the first element where `agentId == 0`, `agentTba` remains `address(0)` and `token.safeTransferFrom` attempts a transfer to the zero address. For later elements where `agentId == 0` follows a non-zero `agentId`, the stale `agentTba` from the previous agent is reused, misdirecting funds.
</details>

---

## Vulnerability Categories

Summary of the types of vulnerabilities Wake Arena detects well, based on benchmark and production data.

| Category | Example Protocols | Example Findings |
|---|---|---|
| **Cross-chain logic** | Lend, DODO | Non-atomic liquidation, stale collateral snapshots, refund auth bypass |
| **Access control** | Crestal, Virtuals, Mellow | Unauthenticated allowance drain, permissionless validator registration, threshold bypass via duplicate signers |
| **Accounting / state** | Lend, Notional, Mellow | Repeated reward claims, incorrect netting, protocol fee double-accrual |
| **Protocol-specific logic** | Munchables, TraitForge, Burve | Dirty flag never cleared, generation counter limits, fee checkpoint mismanagement |
| **Reentrancy / callbacks** | Phi | Sell-lock bypass via refund reentrancy |
| **Parameter validation** | Basin, Blackhole, Lambo.win | Inverted zero-address check, `msg.value` / ERC20 amount mismatch |

---

## Changelog

| Date | Change |
|---|---|
| Dec 10, 2025 | Initial benchmarks published: Wake Arena, Zellic Scanner V12, Plain GPT-5, Plain Opus 4.5 |
| Feb 22, 2026 | Added EvmBench results to the comparison table |

---

*[Wake Arena](https://ackee.xyz/wake/arena) by [Ackee Blockchain](https://ackee.xyz) — 200+ audits, $180B+ in TVL secured.*
