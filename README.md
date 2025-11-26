CryptoCore
Командный инструмент для шифрования файлов и вычисления хэшей, реализующий AES-128 и криптографические хэш-функции.

Возможности
AES-128 шифрование в различных режимах: ECB, CBC, CFB, OFB, CTR

Безопасная генерация случайных ключей с использованием криптографически стойкого ГПСЧ

SHA-256 и SHA3-256 хэш-функции, реализованные с нуля

Вычисление хэшей файлов со стандартным форматом вывода

Совместимость с OpenSSL и системными утилитами

Хэш-алгоритмы
SHA-256: NIST FIPS 180-4, конструкция Меркла-Дамгора

SHA3-256: NIST FIPS 202, губчатая конструкция Keccak

Использование
Шифрование/Дешифрование
# Шифрование с автоматической генерацией ключа
cryptocore encrypt --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

# Дешифрование с указанным ключом
cryptocore encrypt --algorithm aes --mode cbc --decrypt --key 001122...eeff --input file.enc --output file.dec


Вычисление хэшей

# Базовое вычисление хэша в stdout
cryptocore dgst --algorithm sha256 --input document.pdf
# Вывод: 5d5b09f6... document.pdf

# Сохранение хэша в файл
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3


Тестирование

# Запуск всех тестов хэш-функций
python tests/test_hash.py

# Тестирование конкретного алгоритма
python -c "from src.hash.sha256 import sha256_hash; print(sha256_hash(b'abc'))"
# Должно вывести: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad


Детали реализации
SHA-256: 64-раундовая функция сжатия с блоками по 512 бит

SHA3-256: 24-раундовая перестановка Keccak-f[1600]

Оба алгоритма обрабатывают входные данные произвольной длины с правильным дополнением

Обработка файлов порциями для эффективного использования памяти

Зависимости
Python 3.6+

pycryptodome

Безопасность
Использует os.urandom() для криптографически стойкой генерации случайных чисел

Ключи и векторы инициализации генерируются с использованием ГПСЧ операционной системы

Обнаружение слабых ключей с предупреждениями о небезопасных паттернах

Тестирование NIST
Для проверки качества генерации случайных чисел:

Генерация тестовых данных:


python tests/test_csprng.py


Скачивание и компиляция NIST STS:


wget https://csrc.nist.gov/CSRC/media/Projects/Random-Bit-Generation/documents/sts-2_1_2.zip
unzip sts-2_1_2.zip
cd sts-2.1.2
make

Запуск тестов NIST:


./assess 10000000
# Следуйте инструкциям для указания файла 'nist_test_data.bin'
# Просмотрите результаты в `results.txt`


Инструкции по сборке

pip install -r requirements.txt
