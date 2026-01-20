// Dark DEX Protocol Model v2
//
// Модель протокола приватных депозитов на Quint
// Версия: poseidon_instead_of_ecc (без ECC)
//
// ============================================================================
// USER FLOW (как в реальном протоколе):
// ============================================================================
// 1. User имеет sk (секретный ключ)
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
// ВАЖНО: sum и token_type публичны! Приватен только sk.
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
    type Digest = { owner: UserId, token: TokenType, amount: Amount }

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

    // Абстракция Hash: (user, token, amount) -> unique digest
    pure def compute_digest(user: UserId, token: TokenType, amount: Amount): Digest = {
        { owner: user, token: token, amount: amount }
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
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // DEPOSIT: User вносит токены в DEX
    action deposit(user: UserId, token: TokenType, amount: Amount): bool = {
        val user_bal = get_balance(balances, user, token)
        val dig = compute_digest(user, token, amount)
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
            not(deposits.exists(d => d.digest == dig)),
            deposits' = deposits.union(Set(new_dep)),
            balances' = set_balance(balances, user, token, user_bal - amount),
            dex_balances' = set_dex_balance(dex_balances, token, get_dex_balance(dex_balances, token) + amount),
            op_count' = op_count + 1,
            used_proofs' = used_proofs,
            pending_withdraws' = pending_withdraws,
            timestamp' = timestamp + 1
        }
    }

    // WITHDRAW: User выводит токены из DEX (with replay protection)
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

}

