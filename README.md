CryptoCore

Простой инструмент для шифрования, хэширования и проверки целостности данных.
Использует AES-128, хэш-функции и криптографически безопасный генератор случайных чисел.

Что умеет
Шифрование (Milestones 1–2)

AES-128 в режимах: ECB, CBC, CFB, OFB, CTR

Автоматическая генерация IV при шифровании

Корректное чтение IV из файла при расшифровке

PKCS#7-padding там, где он требуется

Совместимость с OpenSSL

Безопасная генерация случайных данных (Milestone 3)

generate_random_bytes() — источник криптографически стойких случайных байт

Автогенерация ключа, если --key не указан

Генерация IV и nonce для режимов шифрования

Хэш-функции (Milestone 4)

Реализация SHA-256 с нуля

Реализация SHA3-256 (Keccak)

Хэширование файлов с выводом в формате:

HASH  filename

HMAC и аутентификация (Milestone 5)

HMAC-SHA256, работающий с файлами

Поддержка ключей любой длины

Генерация HMAC и проверка существующего файла с HMAC

Аутентифицированное шифрование (Milestone 6)

Поддержка AES-GCM

AAD (дополнительные данные, участвующие в проверке)

Автогенерация nonce (12 байт)

Проверка тега при расшифровке
Данные не выводятся, если проверка не прошла

Установка
pip install -r requirements.txt

Примеры использования
Шифрование / расшифровка

Шифрование с автоматическим ключом

cryptocore --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc


Программа выведет сгенерированный ключ.

Расшифровка

cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.enc --output file.dec

Хэширование

SHA-256

cryptocore dgst --algorithm sha256 --input data.bin


SHA3-256 с выводом в файл

cryptocore dgst --algorithm sha3-256 --input data.bin --output hash.txt

HMAC

Создание HMAC

cryptocore dgst --algorithm sha256 --hmac \
  --key 112233aabbccddeeff \
  --input message.txt


Проверка HMAC

cryptocore dgst --algorithm sha256 --hmac \
  --key 112233aabbccddeeff \
  --input message.txt --verify message.hmac

GCM (AES-GCM)

Шифрование с AAD

cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccdd \
  --input file.txt --output file.gcm


Расшифровка

cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad aabbccdd \
  --input file.gcm --output file.dec


Если AAD или данные были подделаны — программа сообщит об ошибке, файл не создастся.

Тестирование
pytest


Отдельные компоненты:

Генератор случайных чисел

python tests/test_csprng.py


Режимы шифрования

python tests/test_modes.py


Хэш-функции

python tests/test_hash.py

Качество случайных чисел (NIST STS)

Проект может подготовить файл для проверки генератора:

python tests/test_csprng.py


Затем можно прогнать его через NIST STS
