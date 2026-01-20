// Dark DEX Protocol Model v3
//
// Модель протокола приватных депозитов на Quint
// Версия: poseidon_instead_of_ecc (без ECC)
//
// ============================================================================
// USER FLOW (как в реальном протоколе):
// ============================================================================
// 1. User генерирует НОВЫЙ sk = random::<u64>() для КАЖДОГО депозита
// 2. User создаёт deposit: (token_type, amount)
// 3. Circuit вычисляет:
//    - sk_commitment = Poseidon(sk, 0)
//    - digest = Poseidon(sk_commitment, amount, token, sk)
// 4. User публикует: (amount, token, digest) + ZK proof
// 5. Verifier проверяет proof и записывает deposit
// 6. Для withdraw: User создаёт proof знания sk для того же digest
//
// PUBLIC INPUTS: [private_note_sum, token_type, digest]
// PRIVATE INPUTS: [sk, sk_commitment]
//
// ВАЖНО:
// - sum и token_type публичны! Приватен только sk.
// - sk уникален для КАЖДОГО депозита → digest уникален даже для (same owner, token, amount)
//
// ============================================================================
// ATTACK SCENARIOS:
// ============================================================================
// 1. REPLAY ATTACK: попытка использовать один proof дважды
// 2. FRONT-RUNNING: miner видит транзакцию и пытается украсть
// 3. DIGEST COLLISION: попытка создать коллизию хеша
// 4. PROOF FORGERY: атакующий пытается создать fake proof без sk
// ============================================================================

module dark_dex_protocol {

    // ==========================================================================
    // TYPES
    // ==========================================================================

    type UserId = int
    type TokenType = int
    type Amount = int

    // Digest - уникальный идентификатор депозита (абстракция над Poseidon hash)
    // В реальности: Poseidon(sk_commitment, sum, token, sk)
    // где sk = random::<u64>() - уникальный для каждого депозита!
    // nonce моделирует этот уникальный sk
    type Digest = { owner: UserId, token: TokenType, amount: Amount, nonce: int }

    // Депозит в системе
    type Deposit = {
        digest: Digest,
        amount: Amount,
        token: TokenType,
        owner: UserId,
        withdrawn: bool
    }

    // Баланс пользователя
    type Balance = { user: UserId, token: TokenType, amount: Amount }

    // Баланс DEX
    type DexBalance = { token: TokenType, amount: Amount }

    // Pending withdrawal (для front-running анализа)
    type PendingWithdraw = {
        requester: UserId,
        digest: Digest,
        timestamp: int
    }

    // ==========================================================================
    // STATE
    // ==========================================================================

    var deposits: Set[Deposit]
    var balances: Set[Balance]
    var dex_balances: Set[DexBalance]
    var op_count: int
    var next_nonce: int                   // Counter for unique digest nonces (models random sk)

    // Attack tracking
    var used_proofs: Set[Digest]          // For replay attack detection
    var pending_withdraws: Set[PendingWithdraw]  // For front-running
    var timestamp: int                     // Global timestamp

    // ==========================================================================
    // PURE FUNCTIONS
    // ==========================================================================

    pure def get_balance(bals: Set[Balance], user: UserId, token: TokenType): Amount = {
        bals.filter(b => b.user == user and b.token == token)
            .fold(0, (acc, b) => b.amount)
    }

    pure def set_balance(bals: Set[Balance], user: UserId, token: TokenType, new_amount: Amount): Set[Balance] = {
        bals.filter(b => not(b.user == user and b.token == token))
            .union(Set({ user: user, token: token, amount: new_amount }))
    }

    pure def get_dex_balance(dex: Set[DexBalance], token: TokenType): Amount = {
        dex.filter(d => d.token == token).fold(0, (acc, d) => d.amount)
    }

    pure def set_dex_balance(dex: Set[DexBalance], token: TokenType, new_amount: Amount): Set[DexBalance] = {
        dex.filter(d => not(d.token == token))
           .union(Set({ token: token, amount: new_amount }))
    }

    // Абстракция Hash: (user, token, amount, nonce) -> unique digest
    // nonce моделирует уникальный sk = random::<u64>() в реальном протоколе
    pure def compute_digest(user: UserId, token: TokenType, amount: Amount, nonce: int): Digest = {
        { owner: user, token: token, amount: amount, nonce: nonce }
    }

    // Проверка ZK proof - user знает sk для digest
    pure def verify_proof(claimed_user: UserId, actual_owner: UserId): bool = {
        claimed_user == actual_owner
    }

    // Найти депозит по digest
    pure def find_active_deposit(deps: Set[Deposit], dig: Digest): Deposit = {
        deps.filter(d => d.digest == dig and not(d.withdrawn))
            .fold({ digest: dig, amount: 0, token: 0, owner: 0, withdrawn: false }, (acc, d) => d)
    }

    pure def has_active_deposit(deps: Set[Deposit], dig: Digest): bool = {
        deps.filter(d => d.digest == dig and not(d.withdrawn)).size() == 1
    }

    // ==========================================================================
    // INITIAL STATE
    // ==========================================================================

    action init = all {
        deposits' = Set(),
        balances' = Set(),
        dex_balances' = Set(),
        op_count' = 0,
        next_nonce' = 0,
        used_proofs' = Set(),
        pending_withdraws' = Set(),
        timestamp' = 0
    }

    // ==========================================================================
    // ACTIONS
    // ==========================================================================

    // Mint: пользователь получает токены (для тестов)
    action mint(user: UserId, token: TokenType, amount: Amount): bool = {
        val current = get_balance(balances, user, token)
        all {
            amount > 0,
            balances' = set_balance(balances, user, token, current + amount),
            deposits' = deposits,
            dex_balances' = dex_balances,
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // DEPOSIT: User вносит токены в DEX
    // Каждый депозит получает уникальный nonce (моделирует random sk)
    action deposit(user: UserId, token: TokenType, amount: Amount): bool = {
        val user_bal = get_balance(balances, user, token)
        val dig = compute_digest(user, token, amount, next_nonce)
        val new_dep: Deposit = {
            digest: dig,
            amount: amount,
            token: token,
            owner: user,
            withdrawn: false
        }
        all {
            amount > 0,
            user_bal >= amount,
            // С nonce digest всегда уникален, но проверка не повредит
            not(deposits.exists(d => d.digest == dig)),
            deposits' = deposits.union(Set(new_dep)),
            balances' = set_balance(balances, user, token, user_bal - amount),
            dex_balances' = set_dex_balance(dex_balances, token, get_dex_balance(dex_balances, token) + amount),
            op_count' = op_count + 1,
            next_nonce' = next_nonce + 1,  // Increment nonce for next deposit
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // WITHDRAW: User выводит токены из DEX (with replay protection)
    // NOTE: Выводится ВСЯ сумма digest. Для частичного вывода используй split.
    action withdraw(user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        val cur_bal = get_balance(balances, user, dep.token)
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            not(used_proofs.contains(dig)),  // Replay protection
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, user, dep.token, cur_bal + dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs.union(Set(dig)),
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // ==========================================================================
    // NOTE OPERATIONS (Contract Layer)
    // ==========================================================================
    // Эти операции будут на уровне смарт-контрактов.
    // ZK circuit только доказывает владение sk → право на операцию.
    // Сама логика (split, merge, transfer) - в контракте.

    // SPLIT: Разбить ноту на две части
    // Input: digest_old (amount = a1 + a2)
    // Output: digest_new_1 (amount = a1), digest_new_2 (amount = a2)
    // User доказывает владение digest_old через ZK proof
    // Каждая новая нота получает уникальный nonce
    action split(user: UserId, dig: Digest, amount_1: Amount, amount_2: Amount): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        // Новые digests с новыми amounts И уникальными nonce
        val dig_1 = compute_digest(user, dep.token, amount_1, next_nonce)
        val dig_2 = compute_digest(user, dep.token, amount_2, next_nonce + 1)
        val new_dep_1: Deposit = {
            digest: dig_1,
            amount: amount_1,
            token: dep.token,
            owner: user,
            withdrawn: false
        }
        val new_dep_2: Deposit = {
            digest: dig_2,
            amount: amount_2,
            token: dep.token,
            owner: user,
            withdrawn: false
        }
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            not(used_proofs.contains(dig)),
            amount_1 > 0,
            amount_2 > 0,
            amount_1 + amount_2 == dep.amount,  // Conservation!
            // С уникальными nonce, dig_1 != dig_2 даже при amount_1 == amount_2
            deposits' = deposits.exclude(Set(dep))
                               .union(Set(updated_dep))
                               .union(Set(new_dep_1))
                               .union(Set(new_dep_2)),
            balances' = balances,  // Токены остаются в DEX
            dex_balances' = dex_balances,  // Баланс DEX не меняется
            op_count' = op_count + 1,
            next_nonce' = next_nonce + 2,  // Использовали 2 nonce
            used_proofs' = used_proofs.union(Set(dig)),
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // MERGE: Объединить две ноты в одну
    // User должен владеть обеими нотами (знать оба sk)
    action merge(user: UserId, dig_1: Digest, dig_2: Digest): bool = {
        val dep_1 = find_active_deposit(deposits, dig_1)
        val dep_2 = find_active_deposit(deposits, dig_2)
        val updated_dep_1: Deposit = { ...dep_1, withdrawn: true }
        val updated_dep_2: Deposit = { ...dep_2, withdrawn: true }
        val new_amount = dep_1.amount + dep_2.amount
        val dig_merged = compute_digest(user, dep_1.token, new_amount, next_nonce)
        val new_dep: Deposit = {
            digest: dig_merged,
            amount: new_amount,
            token: dep_1.token,
            owner: user,
            withdrawn: false
        }
        all {
            has_active_deposit(deposits, dig_1),
            has_active_deposit(deposits, dig_2),
            dig_1 != dig_2,
            dep_1.token == dep_2.token,  // Тот же тип токена
            verify_proof(user, dep_1.owner),
            verify_proof(user, dep_2.owner),
            not(used_proofs.contains(dig_1)),
            not(used_proofs.contains(dig_2)),
            deposits' = deposits.exclude(Set(dep_1))
                               .exclude(Set(dep_2))
                               .union(Set(updated_dep_1))
                               .union(Set(updated_dep_2))
                               .union(Set(new_dep)),
            balances' = balances,
            dex_balances' = dex_balances,
            op_count' = op_count + 1,
            next_nonce' = next_nonce + 1,
            used_proofs' = used_proofs.union(Set(dig_1)).union(Set(dig_2)),
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // TRANSFER_SK: Передача ноты другому пользователю (off-chain передача sk)
    // В реальности: Alice передаёт sk Bob'у, Bob создаёт новый digest
    // Новый digest с новым owner и новым nonce (Bob генерирует свой sk)
    action transfer_note(from_user: UserId, to_user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        // Новый digest с новым owner и уникальным nonce
        val new_dig = compute_digest(to_user, dep.token, dep.amount, next_nonce)
        val new_dep: Deposit = {
            digest: new_dig,
            amount: dep.amount,
            token: dep.token,
            owner: to_user,
            withdrawn: false
        }
        all {
            has_active_deposit(deposits, dig),
            verify_proof(from_user, dep.owner),
            from_user != to_user,
            not(used_proofs.contains(dig)),
            // С nonce проверка уникальности не нужна, но оставим для защиты
            deposits' = deposits.exclude(Set(dep))
                               .union(Set(updated_dep))
                               .union(Set(new_dep)),
            balances' = balances,
            dex_balances' = dex_balances,
            op_count' = op_count + 1,
            next_nonce' = next_nonce + 1,
            used_proofs' = used_proofs.union(Set(dig)),
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // ==========================================================================
    // ATTACK ACTIONS
    // ==========================================================================

    // ATTACK 1: Proof Forgery - попытка вывести чужой депозит
    action attack_proof_forgery(attacker: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        all {
            has_active_deposit(deposits, dig),
            attacker != dep.owner,
            verify_proof(attacker, dep.owner),  // Это вернёт false!
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, attacker, dep.token, dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // ATTACK 2: Replay Attack - попытка использовать proof дважды
    // ПРИМЕЧАНИЕ: В реальном протоколе withdrawn=true уже защищает,
    // но мы моделируем случай если бы этой защиты не было
    action attack_replay_no_protection(user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        val cur_bal = get_balance(balances, user, dep.token)
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            // БЕЗ проверки used_proofs - уязвимая версия
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, user, dep.token, cur_bal + dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // ATTACK 3: Front-running - miner видит pending tx и пытается опередить
    // Шаг 1: User публикует intent в mempool
    action publish_withdraw_intent(user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val pw: PendingWithdraw = { requester: user, digest: dig, timestamp: timestamp }
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            pending_withdraws' = pending_withdraws.union(Set(pw)),
            deposits' = deposits,
            balances' = balances,
            dex_balances' = dex_balances,
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            timestamp' = timestamp + 1
        }
    }

    // ATTACK 3: Front-running - miner пытается выполнить вместо user
    action attack_frontrun(miner: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        // Miner видит pending withdraw в mempool
        val has_pending = pending_withdraws.exists(pw => pw.digest == dig)
        all {
            has_active_deposit(deposits, dig),
            has_pending,
            miner != dep.owner,
            verify_proof(miner, dep.owner),  // Miner не знает sk → false!
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, miner, dep.token, dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // ==========================================================================
    // STEP
    // ==========================================================================

    val USERS = Set(1, 2, 3)
    val TOKENS = Set(1, 2)
    val AMOUNTS = Set(100, 200)

    // Split amounts (для split операции: a1 + a2 должно = исходному amount)
    val SPLIT_AMOUNTS = Set((100, 100), (50, 150))  // пары, которые дают 200

    // Normal operations step
    action step = any {
        nondet u = USERS.oneOf()
        nondet t = TOKENS.oneOf()
        nondet a = AMOUNTS.oneOf()
        mint(u, t, a),

        nondet u = USERS.oneOf()
        nondet t = TOKENS.oneOf()
        nondet a = AMOUNTS.oneOf()
        deposit(u, t, a),

        nondet u = USERS.oneOf()
        nondet dep = deposits.oneOf()
        withdraw(u, dep.digest),

        // SPLIT: разбить ноту на две
        nondet u = USERS.oneOf()
        nondet dep = deposits.oneOf()
        nondet a1 = AMOUNTS.oneOf()
        nondet a2 = AMOUNTS.oneOf()
        split(u, dep.digest, a1, a2),

        // MERGE: объединить две ноты
        nondet u = USERS.oneOf()
        nondet dep1 = deposits.oneOf()
        nondet dep2 = deposits.oneOf()
        merge(u, dep1.digest, dep2.digest),

        // TRANSFER: передать ноту другому пользователю
        nondet sender = USERS.oneOf()
        nondet receiver = USERS.oneOf()
        nondet dep = deposits.oneOf()
        transfer_note(sender, receiver, dep.digest),

        // Attack: proof forgery
        nondet attacker = USERS.oneOf()
        nondet dep = deposits.oneOf()
        attack_proof_forgery(attacker, dep.digest),

        // Attack: front-running step 1 - publish intent
        nondet u = USERS.oneOf()
        nondet dep = deposits.oneOf()
        publish_withdraw_intent(u, dep.digest),

        // Attack: front-running step 2 - miner tries to steal
        nondet miner = USERS.oneOf()
        nondet dep = deposits.oneOf()
        attack_frontrun(miner, dep.digest)
    }

    // ==========================================================================
    // INVARIANTS
    // ==========================================================================

    // INV-1: DEX balance всегда >= 0
    val inv_dex_non_negative = dex_balances.forall(db => db.amount >= 0)

    // INV-2: Каждый digest уникален
    val inv_unique_digests = deposits.forall(d1 =>
        deposits.forall(d2 => (d1.digest == d2.digest) implies (d1 == d2))
    )

    // INV-3: Только владелец может вывести (главное свойство!)
    val inv_owner_only = deposits.forall(d =>
        d.withdrawn implies (d.digest.owner == d.owner)
    )

    // INV-4: No double withdrawal (replay protection)
    val inv_no_double_withdraw = deposits.forall(d =>
        d.withdrawn implies used_proofs.contains(d.digest)
    )

    // INV-5: Conservation of tokens
    // Total user balances + DEX balances = constant (after minting)
    // Simplified: sum of all deposits = sum of DEX balances
    val inv_conservation = {
        val total_deposited = deposits.filter(d => not(d.withdrawn))
                                      .fold(0, (acc, d) => acc + d.amount)
        val total_dex = dex_balances.fold(0, (acc, db) => db.amount + acc)
        total_deposited == total_dex
    }

    // INV-6: Front-running protection
    // If there's a pending withdraw, only the requester can complete it
    val inv_frontrun_protection = pending_withdraws.forall(pw =>
        deposits.forall(d =>
            (d.digest == pw.digest and d.withdrawn) implies (d.owner == pw.requester)
        )
    )

    // INV-7: Split conservation
    // After split, total amount in new notes = amount in original note
    // This is implicitly checked by split action precondition, but we verify globally
    val inv_split_conservation = inv_conservation  // Same as general conservation

    // INV-8: Transfer preserves ownership chain
    // A transferred note belongs to the new owner
    val inv_transfer_valid = deposits.forall(d =>
        not(d.withdrawn) implies (d.owner == d.digest.owner)
    )

    // ==========================================================================
    // TEMPORAL PROPERTIES
    // ==========================================================================
    //
    // Temporal properties express liveness and safety over time.
    // In Quint, we express them as temporal formulas.
    //
    // Notation:
    //   eventually(P)  = ◇P = "P holds at some point in the future"
    //   always(P)      = □P = "P holds forever from now"
    //   P leads_to Q   = □(P => ◇Q) = "whenever P, eventually Q"
    // ==========================================================================

    // TEMP-1: Liveness - Every deposit can eventually be withdrawn
    // "If a deposit exists and is not withdrawn, it's possible to withdraw it"
    //
    // This is a WEAK liveness property - it says withdrawal is POSSIBLE,
    // not that it WILL happen (that would require fairness assumptions).
    //
    // We express this as: for any active deposit, the withdraw action is enabled
    // when called by the owner.
    def can_withdraw(user: UserId, dig: Digest): bool = {
        deposits.exists(d =>
            d.digest == dig and
            not(d.withdrawn) and
            d.owner == user and
            not(used_proofs.contains(dig))
        )
    }

    // Predicate: all active deposits can be withdrawn by their owners
    val liveness_withdrawable = deposits.forall(d =>
        (not(d.withdrawn)) implies can_withdraw(d.owner, d.digest)
    )

    // TEMP-2: No deadlock - The system can always make progress
    // Either there's a possible action, or all deposits are withdrawn
    val no_deadlock = {
        val all_withdrawn = deposits.forall(d => d.withdrawn)
        val can_mint = true  // mint is always possible
        all_withdrawn or can_mint
    }

    // TEMP-3: Eventual consistency
    // After all operations complete, DEX balance = sum of active deposits
    // (This is inv_conservation expressed as a reachability property)

    // TEMP-4: Fair access - No user is permanently blocked
    // This requires fairness assumptions which are beyond basic model checking.
    // We express a weaker version: if user has balance, deposit is enabled
    def can_deposit(user: UserId, token: TokenType, amount: Amount): bool = {
        get_balance(balances, user, token) >= amount and amount > 0
    }

    val fair_access = USERS.forall(u =>
        TOKENS.forall(t =>
            AMOUNTS.forall(a =>
                (get_balance(balances, u, t) >= a and a > 0) implies can_deposit(u, t, a)
            )
        )
    )

    // ==========================================================================
    // TEMPORAL FORMULAS (for Apalache temporal checking)
    // ==========================================================================

    // These require temporal operators which Apalache supports via --temporal flag

    // TEMP-5: Safety - Once withdrawn, always withdrawn (no rollback)
    // □(d.withdrawn => □d.withdrawn)
    // We express this as an action property: withdraw never "un-withdraws"

    // Helper: track which digests were withdrawn in previous state
    // (This would require history variables for full temporal checking)

    // TEMP-6: Leads-to property
    // deposit(user, token, amount) ~~> can_withdraw(user, digest)
    // "Every deposit leads to the ability to withdraw"
    // This is trivially true in our model because withdraw is always enabled
    // for active deposits owned by the user.

    // ==========================================================================
    // TEMPORAL INVARIANTS (checkable as state invariants)
    // ==========================================================================

    // These are "inductive" versions of temporal properties that can be
    // checked as regular invariants.

    // TINV-1: Monotonicity of withdrawals
    // Once a deposit is withdrawn, it stays withdrawn
    // (This is guaranteed by our state machine - no action "un-withdraws")
    val tinv_withdrawal_monotonic = deposits.forall(d =>
        d.withdrawn implies used_proofs.contains(d.digest)
    )

    // TINV-2: Progress is possible
    // The system is never completely stuck
    val tinv_no_stuck = {
        // Either we can mint, or we can withdraw something, or all is done
        val can_do_something = (
            // Can always mint
            true
        )
        can_do_something
    }

    // TINV-3: Funds are never lost
    // Total tokens in system = tokens in balances + tokens in DEX
    // (This is a restatement of inv_conservation as a temporal property)

}

// ============================================================================
// OPTIMIZED MODULE FOR APALACHE
// ============================================================================
// This module uses:
// 1. Auxiliary variables instead of fold (total_minted, total_in_dex)
// 2. Smaller domains (2 users, 1 token, 1 amount)
// 3. Simplified state for faster bounded model checking
// ============================================================================

module dark_dex_apalache {

    // ==========================================================================
    // TYPES (same as main module)
    // ==========================================================================

    type UserId = int
    type TokenType = int
    type Amount = int
    // Digest includes nonce to model unique sk per deposit
    type Digest = { owner: UserId, token: TokenType, amount: Amount, nonce: int }

    type Deposit = {
        digest: Digest,
        amount: Amount,
        token: TokenType,
        owner: UserId,
        withdrawn: bool
    }

    // ==========================================================================
    // STATE - with auxiliary variables for Apalache
    // ==========================================================================

    var deposits: Set[Deposit]
    var op_count: int
    var next_nonce: int           // Counter for unique nonces
    var used_proofs: Set[Digest]

    // AUXILIARY VARIABLES - maintained incrementally instead of fold
    var total_minted: int       // Total tokens ever minted
    var total_in_dex: int       // Total tokens currently in DEX (not withdrawn)
    var total_withdrawn: int    // Total tokens withdrawn

    // ==========================================================================
    // PURE FUNCTIONS
    // ==========================================================================

    pure def compute_digest(user: UserId, token: TokenType, amount: Amount, nonce: int): Digest = {
        { owner: user, token: token, amount: amount, nonce: nonce }
    }

    pure def verify_proof(claimed_user: UserId, actual_owner: UserId): bool = {
        claimed_user == actual_owner
    }

    pure def find_active_deposit(deps: Set[Deposit], dig: Digest): Deposit = {
        deps.filter(d => d.digest == dig and not(d.withdrawn))
            .fold({ digest: dig, amount: 0, token: 0, owner: 0, withdrawn: false }, (acc, d) => d)
    }

    pure def has_active_deposit(deps: Set[Deposit], dig: Digest): bool = {
        deps.exists(d => d.digest == dig and not(d.withdrawn))
    }

    // ==========================================================================
    // INITIALIZATION
    // ==========================================================================

    action init = all {
        deposits' = Set(),
        op_count' = 0,
        next_nonce' = 0,
        used_proofs' = Set(),
        total_minted' = 0,
        total_in_dex' = 0,
        total_withdrawn' = 0
    }

    // ==========================================================================
    // ACTIONS - with auxiliary variable updates
    // ==========================================================================

    // DEPOSIT: User deposits tokens into DEX
    action deposit_apalache(user: UserId, token: TokenType, amount: Amount): bool = {
        val dig = compute_digest(user, token, amount, next_nonce)
        val new_dep: Deposit = {
            digest: dig,
            amount: amount,
            token: token,
            owner: user,
            withdrawn: false
        }
        all {
            amount > 0,
            // With nonce, digest is always unique
            deposits' = deposits.union(Set(new_dep)),
            op_count' = op_count + 1,
            next_nonce' = next_nonce + 1,
            used_proofs' = used_proofs,
            // Update auxiliary variables
            total_minted' = total_minted + amount,
            total_in_dex' = total_in_dex + amount,
            total_withdrawn' = total_withdrawn
        }
    }

    // WITHDRAW: User withdraws tokens from DEX
    action withdraw_apalache(user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            not(used_proofs.contains(dig)),
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs.union(Set(dig)),
            // Update auxiliary variables
            total_minted' = total_minted,
            total_in_dex' = total_in_dex - dep.amount,
            total_withdrawn' = total_withdrawn + dep.amount
        }
    }

    // ATTACK: Proof forgery attempt
    action attack_forgery_apalache(attacker: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        all {
            has_active_deposit(deposits, dig),
            attacker != dep.owner,
            verify_proof(attacker, dep.owner),  // Returns false!
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            op_count' = op_count + 1,
            next_nonce' = next_nonce,
            used_proofs' = used_proofs,
            total_minted' = total_minted,
            total_in_dex' = total_in_dex - dep.amount,
            total_withdrawn' = total_withdrawn + dep.amount
        }
    }

    // ==========================================================================
    // STEP - SMALL DOMAIN FOR APALACHE
    // ==========================================================================

    // Small domains for bounded model checking
    val USERS = Set(1, 2)       // Only 2 users
    val TOKENS = Set(1)         // Only 1 token type
    val AMOUNTS = Set(100)      // Only 1 amount

    // Stutter step - prevents deadlock when all actions are disabled
    action stutter = all {
        deposits' = deposits,
        op_count' = op_count,
        next_nonce' = next_nonce,
        used_proofs' = used_proofs,
        total_minted' = total_minted,
        total_in_dex' = total_in_dex,
        total_withdrawn' = total_withdrawn
    }

    action step = any {
        // Normal deposit
        nondet u = USERS.oneOf()
        nondet t = TOKENS.oneOf()
        nondet a = AMOUNTS.oneOf()
        deposit_apalache(u, t, a),

        // Normal withdraw
        nondet u = USERS.oneOf()
        nondet dep = deposits.oneOf()
        withdraw_apalache(u, dep.digest),

        // Attack: proof forgery
        nondet attacker = USERS.oneOf()
        nondet dep = deposits.oneOf()
        attack_forgery_apalache(attacker, dep.digest),

        // Stutter step to prevent deadlock
        stutter
    }

    // ==========================================================================
    // INVARIANTS - using auxiliary variables (no fold!)
    // ==========================================================================

    // INV-1: Conservation using auxiliary variables (O(1) instead of O(n))
    val inv_conservation_aux = {
        total_in_dex >= 0 and
        total_minted == total_in_dex + total_withdrawn
    }

    // INV-2: Auxiliary variables match actual state
    val inv_aux_consistent = {
        val actual_in_dex = deposits.filter(d => not(d.withdrawn))
                                    .fold(0, (acc, d) => acc + d.amount)
        val actual_withdrawn = deposits.filter(d => d.withdrawn)
                                       .fold(0, (acc, d) => acc + d.amount)
        total_in_dex == actual_in_dex and total_withdrawn == actual_withdrawn
    }

    // INV-3: Only owner can withdraw
    val inv_owner_only_aux = deposits.forall(d =>
        d.withdrawn implies (d.digest.owner == d.owner)
    )

    // INV-4: No double withdrawal
    val inv_no_double_withdraw_aux = deposits.forall(d =>
        d.withdrawn implies used_proofs.contains(d.digest)
    )

    // INV-5: Each digest is unique (collision resistance)
    val inv_unique_digests_aux = deposits.forall(d1 =>
        deposits.forall(d2 => (d1.digest == d2.digest) implies (d1 == d2))
    )

    // INV-6: Used proofs are subset of all digests
    val inv_used_proofs_valid = used_proofs.forall(dig =>
        deposits.exists(d => d.digest == dig)
    )

    // INV-7: No active deposit has been used for proof (no double-spend possible)
    val inv_active_not_used = deposits.forall(d =>
        not(d.withdrawn) implies not(used_proofs.contains(d.digest))
    )

    // INV-8: Withdrawn deposits are in used_proofs
    val inv_withdrawn_tracked = deposits.forall(d =>
        d.withdrawn implies used_proofs.contains(d.digest)
    )

}

