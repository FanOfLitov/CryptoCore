# $env:PYTHONPATH = (Get-Location).Path
#
# Write-Host "BASIC TESTS"
# python -m tests.test_basik
# python -m tests.test_modes
#
# Write-Host " HASH / HMAC"
# python -m tests.test_hash
# python -m tests.test_hmac
#
# Write-Host " AEAD"
# python -m tests.test_aead
#
# Write-Host " KDF "
# python -m tests.test_pbkdf2
# python -m tests.test_hkdf
#
# Write-Host "ALL TESTS COMPLETED"
$env:PYTHONPATH = (Get-Location).Path
python -m tests.test_basik
python -m tests.test_modes
python -m tests.test_hash
python -m tests.test_hmac
python -m tests.test_aead
python -m tests.test_pbkdf2
python -m tests.test_hkdf