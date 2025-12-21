CryptoCore — учебный криптопроект (AES modes / SHA / HMAC / AEAD / KDF)
=====================================================================


1. Краткое описание

CryptoCore — консольный инструмент на Python, реализующий:

1) Симметричное шифрование AES:
   - ECB (с PKCS#7 padding)
   - CBC
   - CFB
   - OFB
   - CTR

2) Хэш‑функции (реализации “с нуля”):
   - SHA‑256
   - SHA3‑256

3) Аутентификация:
   - HMAC‑SHA256 (RFC 2104)
   - Проверка подписи (--verify)

4) AEAD (аутентифицированное шифрование):
   - Encrypt‑then‑MAC (EtM): сначала шифруем, затем считаем HMAC по шифртексту
   - На расшифровке: сначала проверяем HMAC, и только потом расшифровываем

5) KDF (вывод ключей):
   - PBKDF2‑HMAC‑SHA256 (RFC 8018) — из пароля в мастер‑ключ
   - HKDF (RFC 5869) — из мастер‑ключа в независимые ключи для шифрования и MAC

2. Структура проекта


CryptoCore/
 ├─ src/

 
 │   ├─ __init__.py
 
 │   ├─ main.py      # точка входа CLI
 │   ├─ cli_parser.py           # argparse + валидация аргументов
 
 │   ├─ file_io.py              # чтение/запись файлов, PKCS#7 pad/unpad
 
 │   ├─ csprng.py               # генерация ключей/IV/nonce через os.urandom
 
 │   ├─ modes/                  # режимы AES: ecb/cbc/cfb/ofb/ctr

 
 │   ├─ hash/                   # sha256 и sha3_256
 
 │   ├─ mac/                    # hmac
 
 │   ├─ aead/                   # etm (Encrypt-then-MAC)
 
 │   └─ kdf/                    # pbkdf2 и hkdf
 
 ├─ tests/
 │   ├─ __init__.py
 │   ├─ test_basik.py           # базовые тесты (ECB/padding/файлы)
 
 │   ├─ test_modes.py           # CBC/CFB/OFB/CTR round-trip
 
 │   ├─ test_hash.py            # SHA-256/SHA3-256 тест-вектора и avalanche
 
 │   ├─ test_hmac.py            # HMAC тест-вектора + verify
 
 │   ├─ test_aead.py            # AEAD EtM + tamper tests
 
 │   ├─ test_pbkdf2.py          # PBKDF2 RFC тест-вектор
 
 │   └─ test_hkdf.py            # HKDF RFC тест-вектор
 
 ├─ docs/                       # документация (опционально)
 
 └─ README_RU.txt               # этот файл
 

3. Требования и запуск


3.1. Python
- Python 3.x

3.2. Запуск CLI
Все команды выполняйте из КОРНЯ проекта (папка CryptoCore):

  python -m src.main --help

Почему так:
- мы запускаем проект как пакет (python -m), чтобы импорты работали одинаково везде.

4. Команды CLI
--------------
В проекте есть две основные команды:
1) encrypt  — шифрование/дешифрование AES
2) dgst     — хэширование и HMAC

Примеры ниже предполагают, что вы находитесь в корне проекта.

4.1. Хэширование (dgst)

SHA-256:
  python -m src.main dgst --algorithm sha256 --input test.txt

SHA3-256:
  python -m src.main dgst --algorithm sha3-256 --input test.txt

Вывод обычно в формате:
  <hex_hash> <filename>

4.2. HMAC (dgst --hmac)

HMAC-SHA256 от файла:
  python -m src.main dgst --algorithm sha256 --hmac --key <HEX_KEY> --input test.txt

Где <HEX_KEY> — ключ в hex (обычно 64 hex символа для 32 байт или любой длины, если вы так разрешили).

Проверка HMAC:
1) Сначала создайте файл подписи:
   python -m src.main dgst --algorithm sha256 --hmac --key <HEX_KEY> --input test.txt > test.hmac

2) Затем проверьте:
   python -m src.main dgst --algorithm sha256 --hmac --key <HEX_KEY> --input test.txt --verify test.hmac

Результат:
  [OK] HMAC verification successful
или
  [ERROR] HMAC verification failed

ВАЖНО (Windows / PowerShell):
- PowerShell “> file” часто пишет текст в UTF-16. Поэтому verify реализован устойчиво:
  он извлекает первые 64 hex-символа из файла подписи и сравнивает с вычисленным тегом.

4.3. Шифрование (encrypt)

Базовый формат:
  python -m src.main encrypt --algorithm aes --mode <MODE> --encrypt --key <HEX_KEY> --input plain.txt --output out.bin
  python -m src.main encrypt --algorithm aes --mode <MODE> --decrypt --key <HEX_KEY> --input out.bin --output dec.txt

MODE ∈ { ecb, cbc, cfb, ofb, ctr }

Пример CBC:
  python -m src.main encrypt --algorithm aes --mode cbc --encrypt --key 001122... --input test.txt --output test.enc
  python -m src.main encrypt --algorithm aes --mode cbc --decrypt --key 001122... --input test.enc --output test.dec

Про IV/nonce:
- В режимах CBC/CFB/OFB/CTR обычно используется IV/nonce, который генерируется CSPRNG
  и записывается в начало шифртекста. Поэтому дешифрование “знает”, что брать из начала.

4.4. AEAD (Encrypt-then-MAC) — Milestone 6

AEAD включается флагом --aead.

Идея:
- Сначала шифруем выбранным режимом (например CBC/CTR)
- Затем считаем HMAC по (IV|ciphertext) и дописываем тег в конец
- При расшифровке сначала проверяем тег, и только потом расшифровываем

Пример:
  python -m src.main encrypt --algorithm aes --mode cbc --encrypt --aead --key <MASTER_HEX> --input test.txt --output test.aead
  python -m src.main encrypt --algorithm aes --mode cbc --decrypt --aead --key <MASTER_HEX> --input test.aead --output test.dec

Формат выходного файла AEAD:
  (IV|ciphertext) || TAG
где TAG = 32 байта (HMAC-SHA256)

Если изменить хотя бы 1 байт в файле test.aead, расшифровка должна завершиться ошибкой:
  Authentication failed (HMAC tag mismatch)

5. KDF — Milestone 7 (PBKDF2 + HKDF)

5.1. PBKDF2 (пароль → мастер‑ключ)
PBKDF2 используется, чтобы получить криптографически сильный ключ из пароля.

В проекте реализован PBKDF2-HMAC-SHA256 по RFC 8018.

Параметры:
- password: байты пароля
- salt: случайная “соль” (байты)
- iterations: число итераций (например 100000+)
- dklen: длина результата (например 32 байта)

5.2. HKDF (мастер‑ключ → key_enc + key_mac)
HKDF используется для корректного разделения ключей:
- key_enc: ключ шифрования (например 16 байт для AES-128)
- key_mac: ключ аутентификации (например 32 байта для HMAC-SHA256)

В AEAD EtM это критично: нельзя использовать один и тот же ключ и для AES, и для HMAC.

6. Тестирование

Все тесты запускаются из корня проекта:

  python -m tests.test_basik
  python -m tests.test_modes
  python -m tests.test_hash
  python -m tests.test_hmac
  python -m tests.test_aead
  python -m tests.test_pbkdf2
  python -m tests.test_hkdf

Что проверяют тесты:
- test_basik: PKCS#7 padding, ECB round-trip, файловые операции
- test_modes: round-trip для CBC/CFB/OFB/CTR
- test_hash: NIST test vectors, avalanche, file hashing, interoperability (где возможно)
- test_hmac: тест‑вектора RFC + verify
- test_aead: AEAD EtM round-trip + tamper (изменение ciphertext/IV/tag должно ломать расшифровку)
- test_pbkdf2: PBKDF2 RFC тест-вектор
- test_hkdf: HKDF RFC тест-вектор

7. Типовые проблемы и решения

7.1. “No module named 'src'”
- Запускайте из корня проекта и через -m:
  python -m src.main ...
  python -m tests.test_...

7.2. “attempted relative import beyond top-level package”
- Это означает, что где-то используются относительные импорты (..), а модуль запускается не как пакет.
- Рекомендуемая схема: абсолютные импорты через src.* и запуск через python -m.

7.3. Verify HMAC падает в Windows
- В PowerShell редирект “>” может писать в UTF-16.
- В проекте verify реализован устойчиво: достаёт первые 64 hex-символа из файла подписи.

8. Соответствие мейлстоунам 

Milestone 1: AES-ECB + PKCS#7 + CLI + базовые тесты
Milestone 2: CBC/CFB/OFB/CTR + тесты режимов
Milestone 3: CSPRNG (os.urandom) + тесты
Milestone 4: SHA-256 и SHA3-256 + тест-вектора + file hashing
Milestone 5: HMAC-SHA256 + verify + RFC тесты
Milestone 6: AEAD через Encrypt-then-MAC + tamper tests
Milestone 7: PBKDF2 + HKDF + RFC тесты + интеграция
Milestone 8: Документация, полировка, единый способ запуска, инструкции по тестам

<img width="1296" height="669" alt="image" src="https://github.com/user-attachments/assets/0f504dd9-878b-44a2-8df7-0e103ba386ea" />

