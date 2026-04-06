@echo off
echo ============================================================
echo  ENPM693 Homework 4 - RSA Attack Demo
echo ============================================================

echo.
echo [STEP 1] Installing dependencies...
py -m pip install pycryptodome requests -q

echo.
echo ============================================================
echo  KEY 1 - OpenSSL Inspection (255-bit key)
echo ============================================================
openssl rsa -pubin -in key1_public.pem -text -noout

echo.
echo ============================================================
echo  KEY 2A - OpenSSL Inspection (1024-bit key)
echo ============================================================
openssl rsa -pubin -in key2a_public.pem -text -noout

echo.
echo ============================================================
echo  KEY 2B - OpenSSL Inspection (1024-bit key)
echo ============================================================
openssl rsa -pubin -in key2b_public.pem -text -noout

echo.
echo ============================================================
echo  ATTACK 1 - Small Prime Factorization on Key 1
echo ============================================================
set PYTHONIOENCODING=utf-8
py rsa_breaker.py --mode key1 --publickey key1_public.pem --cipherfile key1_cipher.bin

echo.
echo ============================================================
echo  ATTACK 2 - Shared Prime GCD on Key 2A and Key 2B
echo ============================================================
py rsa_breaker.py --mode key2 --publickey key2a_public.pem key2b_public.pem --cipherfile key2a_cipher.bin key2b_cipher.bin

echo.
echo ============================================================
echo  Done. Take your screenshots now.
echo ============================================================
pause
