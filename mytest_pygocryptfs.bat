@echo off
echo Testing pygocryptfs
rd /s /q mytest >nul 2>&1
md mytest >nul

SET DNAME=/Nome di directory lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di gocryptfs in modo da generare un nome di file cifrato lungo
SET FNAME=/Nome di file lungo, anzi, lunghissimo, ossia dal nome veramente lunghissimissimo e tale da venire codificato con oltre 255 caratteri dal codec Base64 di gocryptfs in modo da generare un nome di file cifrato lungo.bat

REM vault_path is the FIRST positional argument, before any flags
SET P=py -m pygocryptfs mytest --password=pippo

echo.
echo ++ Testing vault initialization
py -m pygocryptfs --init --password=pippo mytest

echo.
echo ++ Testing master key printing (hex, default)
py -m pygocryptfs mytest --password=pippo --print-key

echo.
echo ++ Testing master key printing (b64)
py -m pygocryptfs mytest --password=pippo --print-key b64

echo.
echo ++ Testing encryption
%P% encrypt mytest_pygocryptfs.bat "%FNAME%"

echo.
echo ++ Testing directory making
%P% mkdir "%DNAME%"

echo.
echo ++ Testing long names handling
%P% encrypt mytest_pygocryptfs.bat "%DNAME%/mytest.bat"

echo.
echo ++ Testing recursive listing
%P% ls -r /

echo.
echo ++ Testing decryption to STDOUT
%P% decrypt "%DNAME%/mytest.bat" -

echo.
echo ++ Testing alias
%P% alias "%DNAME%/mytest.bat"

echo.
echo ++ Testing rename
%P% mv "%DNAME%/mytest.bat" "%DNAME%/mytest2.bat"

echo.
echo ++ Testing fsck (structural, fast)
py -m pygocryptfs mytest --password=pippo --fsck

echo.
echo ++ Testing removing files and directory
%P% rm "%DNAME%/mytest2.bat"
%P% rm "%DNAME%"
%P% rm "%FNAME%"

echo.
echo ++ Testing listing after cleanup (should be empty)
%P% ls /

echo.
echo ++ Testing backup of diriv files
%P% backup mytest_dirids.zip

echo.
echo ++ Done.
exit /b
