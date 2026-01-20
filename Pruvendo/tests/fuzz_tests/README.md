# Fuzz Tests для DarkDEX Halo2 Circuit

**Обновлено:** 2026-01-21
**Архитектура:** poseidon_instead_of_ecc
**Targets:** 31 (29 stable + 2 known BC)

## Обзор

Coverage-guided fuzzing для ZK-схемы DarkDEX.
Fuzz targets находятся в `Pruvendo/fuzz/`.

## Требования

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Основные Fuzz Targets

| Target | Что тестирует | Статус |
|--------|---------------|--------|
| `fuzz_soundness` | Wrong sk rejected | ✅ |
| `fuzz_completeness` | Valid sk accepted | ✅ |
| `fuzz_poseidon_consistency` | Hash determinism | ✅ |
| `fuzz_digest_collision` | Collision resistance | ✅ |
| `fuzz_verifier_bytes` | Corrupted VK handling | ⚠️ BC-001 |
| `fuzz_proving_key_bytes` | Corrupted params | ⚠️ BC-003 |

## Запуск

```bash
# Из корня проекта:
cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_soundness

# С ограничением времени (30 сек):
cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_soundness -- -max_total_time=30

# Smoke test всех targets:
for t in $(cargo +nightly fuzz list --fuzz-dir Pruvendo/fuzz); do
  cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz $t -- -max_total_time=5
done
```

## Известные BC (upstream)

- **BC-001**: halo2curves panic на corrupted VK bytes
- **BC-003**: halo2_proofs panic на corrupted KZG params

Это проблемы в upstream библиотеках, не в Dark DEX.

## Подробнее

См. [FUZZING_REPORT.md](../../docs/FUZZING_REPORT.md) для полного списка targets.
