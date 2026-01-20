# Анализ результатов фаззинга (архив)

**Дата анализа**: 15-21 января 2026
**Архитектура**: poseidon_instead_of_ecc
**Статус**: ✅ Анализ завершён

---

## Актуальный статус BC

> **ВАЖНО**: После рефакторинга `poseidon_instead_of_ecc` многие находки закрыты!

| BC | Статус | Причина |
|----|--------|---------|
| ~~BC-007~~ | ❌ CLOSED | `vault_rand_val` убран из формулы |
| BC-001 | ⚠️ Актуален | Upstream issue (halo2curves) |
| BC-003/BC-005 | ⚠️ Актуален | Upstream issue (halo2_proofs) |

---

## Актуальные upstream issues

### BC-001: halo2curves panic на corrupted VK

**Причина**: `UnexpectedEof` при чтении коротких/невалидных данных
**Статус**: Upstream issue, не влияет на soundness

### BC-003/BC-005: halo2_proofs panic на corrupted params

**Причина**: `shl_overflow` при чтении corrupted KZG params
**Статус**: Upstream issue, не влияет на soundness

---

## Закрытые находки (исторические)

### ~~CRASH-001/002: fuzz_digest_collision~~ (CLOSED)

**Было**: Коллизии в `deposit_sum = token + sum + vault`
**Статус**: ❌ **CLOSED** — `vault_rand_val` убран из формулы
**Новая формула**: `digest = Poseidon(sk_commitment, sum, token, sk)`

---

## Общий вывод

Фаззинг не выявил критических soundness уязвимостей в Dark DEX.

Все актуальные BC — это upstream issues в зависимостях:
- **halo2curves**: panic при десериализации corrupted данных
- **halo2_proofs**: panic при чтении corrupted KZG params

Эти проблемы не влияют на soundness схемы, только на robustness при обработке невалидных входов.
