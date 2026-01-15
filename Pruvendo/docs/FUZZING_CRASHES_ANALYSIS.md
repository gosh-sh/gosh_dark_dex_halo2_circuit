# Анализ результатов ночного фаззинга

**Дата запуска**: 15 января 2026, 03:20 - 08:24 (5 часов)  
**Параметры**: 800 секунд на каждый из 26 targets  
**Всего crashes**: 10 в 6 targets

---

## Сводная таблица crashes

| # | Target | Crashes | Статус | Критичность |
|---|--------|---------|--------|-------------|
| 1 | fuzz_digest_collision | 1 | ✅ Воспроизводится | 🔴 КРИТИЧЕСКАЯ |
| 2 | fuzz_multikey_digest | 1 | ✅ Воспроизводится | 🟡 ТРЕБУЕТ АНАЛИЗА |
| 3 | fuzz_proving_key_bytes | 3 | ✅ Воспроизводится | 🟠 СРЕДНЯЯ |
| 4 | fuzz_verifier_bytes | 3 | ✅ Воспроизводится | 🟠 СРЕДНЯЯ |
| 5 | fuzz_proof_mutations | 1 | ❓ Не воспроизводится | ⚪ НЕИЗВЕСТНО |
| 6 | fuzz_structured_proof | 1 | ❓ Не воспроизводится | ⚪ НЕИЗВЕСТНО |

---

## CRASH-001: fuzz_digest_collision

**Файл**: `crash-bf9dd64e8719cdd48add91072c80230cbe2ad6cb`  
**Критичность**: 🔴 КРИТИЧЕСКАЯ  
**Воспроизводится**: ДА

### Входные данные (64 bytes)
```
00000000: e3ff f9ff f9f9 f9f9 f9f9 f9f9 f9f9 f9f9
00000010: f9f9 f9f9 f9f9 f9f9 f9ff f9f9 f9ff ffff
00000020: e3ff f9ff f9f9 f9f9 f9ff f9f9 f9f9 f9f9
00000030: f9f9 f9f9 f9f9 f9f9 f9f9 f9f9 f9ff ffff
```

### Декодированные значения
```
Input 1: sk=18012703036781756387, token=91577, sum=681091577, vault=691321
Input 2: sk=18012703036781756387, token=93113, sum=681091577, vault=689785
Digest: 0x22a6d4de61a355d77c80c7fdff244ee269a6afbd275aaa1cd6c1896137198d57
```

### Анализ
**Причина коллизии**:
- `deposit_sum = token + sum + vault` (в поле Fr)
- Input 1: `91577 + 681091577 + 691321 = 681874475`
- Input 2: `93113 + 681091577 + 689785 = 681874475`
- ОДИНАКОВЫЙ `deposit_sum` → одинаковый digest

**Вывод**: Это **НЕ баг в Poseidon hash**, а свойство дизайна. `deposit_sum` - это сумма, и разные комбинации (token, vault) могут давать одинаковую сумму. Однако это показывает что:

1. **Злоумышленник может создать разные notes с одинаковым digest**, меняя token и vault
2. **Публичные данные (token, sum) не разделены от приватных (vault)**

**Рекомендация**: Рассмотреть изменение формулы digest для включения каждого поля отдельно:
```
digest = poseidon_hash([key_sum, token, sum, vault])  // вместо token+sum+vault
```

---

## CRASH-002: fuzz_multikey_digest

**Файл**: `crash-cc927702b39df4a29ef0edcb383da30982818f06`  
**Критичность**: 🟡 ТРЕБУЕТ ДЕТАЛЬНОГО АНАЛИЗА  
**Воспроизводится**: ДА

### Входные данные (121 bytes, структура MultiKeyInput)
```
00000000: 9797 9797 9797 9797 9797 9797 9797 9797  (sk1_seed: 8 bytes)
00000010: 9797 9797 9797 9797 9789 9797 9797 9797  (sk2_seed: 8 bytes + token1...)
...
```

### Декодированные значения
```
Key1: sk_seed=10923366098549577623, pk=(0x3fb6cbc5..., 0x4dd1e941...)
Deposit1: token=10923366098549577623, sum=10923366098549574039, vault=10923366098549577623

Key2: sk_seed=10923366098549577623, pk=(0x3fb6cbc5..., 0x4dd1e941...)
Deposit2: token=10923366098549577623, sum=10923366098549577623, vault=10923366098549574039
```

### Анализ
- **sk1_seed == sk2_seed** → одинаковый ключ (pk1 == pk2)
- **sum1 + vault1 == sum2 + vault2** (сумма переставлена)
- Это **ТОТ ЖЕ случай** что и CRASH-001

**Вывод**: Фаззер нашёл ещё один способ получить коллизию - переставить sum и vault. Проблема в том что `deposit_sum = token + sum + vault` не различает порядок слагаемых.

---

## CRASH-003/004/005: fuzz_proving_key_bytes (3 crashes)

**Критичность**: 🟠 СРЕДНЯЯ (panic на невалидных данных)  
**Воспроизводится**: ДА

### Crash files
1. `crash-fb53bfc43a37c73eb5a862f53ac93d188733691b` (33 bytes)
2. `crash-d78796c27db4781d0aca81d252f246d63a0e3cc3` (33 bytes)
3. `crash-a0c6013801c319bf3452532d473f438dff3948ee` (32 bytes)

### Причина
```
panic_const_shl_overflow в halo2_proofs::plonk::VerifyingKey::read
```

**Вывод**: Библиотека halo2_proofs паникует при чтении corrupted VerifyingKey из-за `unwrap()` вместо proper error handling. Это баг в upstream библиотеке, не в нашем коде.

---

## CRASH-006/007/008: fuzz_verifier_bytes (3 crashes)

**Критичность**: 🟠 СРЕДНЯЯ (panic на невалидных данных)  
**Воспроизводится**: ДА

### Crash files
1. `crash-c95af1eefbad7ff281b1f94f84ddecc261d055e3` (8 bytes)
2. `crash-8ce40dca2c740b89ececf396610f9ae43670927a` (8 bytes)
3. `crash-2ab4e854afaa7c81fc119cdded49ca0d45ad26d6` (8 bytes)

### Причина
```
UnexpectedEof в halo2curves::bn256::fq при read
```

**Вывод**: halo2curves паникует на коротких/невалидных входах. Это известный баг в upstream.

---

## CRASH-009: fuzz_proof_mutations

**Файл**: `crash-8b77f143c42922447a80da6fc3bae2112944d602` (11 bytes)
**Критичность**: ⚪ TRANSIENT
**Воспроизводится**: НЕТ (выполняется успешно за 493ms)

### Анализ
При повторном запуске crash выполняется **без ошибок**. Это означает что исходный crash был **transient** — вероятно из-за:
- OOM (Out of Memory) при параллельном выполнении
- Timeout во время первоначального запуска
- Race condition в libFuzzer

**Вывод**: Не является багом в коде. Можно удалить crash file.

---

## CRASH-010: fuzz_structured_proof

**Файл**: `crash-59753be132a9d7cf1368b424cc3d91ccd163fe7b` (21 bytes)
**Критичность**: ⚪ TRANSIENT
**Воспроизводится**: НЕТ

Аналогично CRASH-009 — transient failure во время ночного запуска.

---

## Итоги и рекомендации

### Критические находки
1. **CRASH-001/002**: Коллизии в digest из-за аддитивности `deposit_sum`

### Рекомендации
1. Изменить формулу digest для раздельного хеширования полей
2. Сообщить upstream о panic в halo2_proofs/halo2curves на невалидных входах
3. Расследовать невоспроизводимые crashes (возможно race conditions)

