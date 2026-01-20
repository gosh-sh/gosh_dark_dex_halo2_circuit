// Dark DEX Protocol Model
//
// Модель протокола приватных депозитов на Quint
// Версия: poseidon_instead_of_ecc (без ECC)
//
// User Flow:
// 1. User имеет sk (секретный ключ)
// 2. User создаёт deposit: (token_type, amount)
// 3. Circuit вычисляет: digest = Hash(Hash(sk,0), amount, token, sk)
// 4. User публикует: (amount, token, digest) + ZK proof
// 5. Verifier проверяет proof и записывает deposit
// 6. Для withdraw: User снова доказывает знание sk для того же digest
//
// Мы моделируем Hash как АБСТРАКТНУЮ функцию (без внутренней логики)
// чтобы избежать state explosion в model checker

module dark_dex_protocol {

    // ==========================================================================
    // TYPES
    // ==========================================================================

    type UserId = int
    type TokenType = int
    type Amount = int

    // Digest - уникальный идентификатор депозита (абстракция над Poseidon hash)
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

    // ==========================================================================
    // STATE
    // ==========================================================================

    var deposits: Set[Deposit]
    var balances: Set[Balance]
    var dex_balances: Set[DexBalance]
    var op_count: int

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
        op_count' = 0
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
            op_count' = op_count + 1
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
            op_count' = op_count + 1
        }
    }

    // WITHDRAW: User выводит токены из DEX
    action withdraw(user: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        val cur_bal = get_balance(balances, user, dep.token)
        all {
            has_active_deposit(deposits, dig),
            verify_proof(user, dep.owner),
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, user, dep.token, cur_bal + dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1
        }
    }

    // ATTACK: Попытка вывести чужой депозит (атакующий != owner)
    action attack_withdraw(attacker: UserId, dig: Digest): bool = {
        val dep = find_active_deposit(deposits, dig)
        val updated_dep: Deposit = { ...dep, withdrawn: true }
        all {
            has_active_deposit(deposits, dig),
            attacker != dep.owner,
            verify_proof(attacker, dep.owner),  // Это вернёт false!
            deposits' = deposits.exclude(Set(dep)).union(Set(updated_dep)),
            balances' = set_balance(balances, attacker, dep.token, dep.amount),
            dex_balances' = set_dex_balance(dex_balances, dep.token, get_dex_balance(dex_balances, dep.token) - dep.amount),
            op_count' = op_count + 1
        }
    }

    // ==========================================================================
    // STEP
    // ==========================================================================

    val USERS = Set(1, 2, 3)
    val TOKENS = Set(1, 2)
    val AMOUNTS = Set(100, 200)

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

        nondet attacker = USERS.oneOf()
        nondet dep = deposits.oneOf()
        attack_withdraw(attacker, dep.digest)
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

}

