# MISRA C compliance

MISRA C was checked using version 2012. The tool PC-Lint was used to verify the
code conforms to the 2012 MISRA C standards. Currently a subset of the wolfCrypt
files are checked (sha256.c, aes.c (CBC/GCM), rsa.c, random.c, sp_c64.c), let us
know if your project requires other files and we can target them while expanding
coverage.

The current wolfSSL build that was used on a 64bit machine is:

```
./configure --enable-sp --enable-aesgcm --enable-staticmemory
```

Then to collect the PC-Lint results use the file IDE/MISRAC/wolfssl.lnt:

```
lint-nt '-os(LINT.TMP)' '/path/to/pc-lint/au-misra3.lnt' '/path/to/pc-lint/co-gcc.lnt IDE/MISRAC/wolfssl.lnt
```


### Deviations

All exceptions to "required" warnings:

| RULE              | FILES              | REASON    | LOCATION COMMENTED IN CODE |
|-------------------|--------------------|-----------|----------------------------|
| Rule 3.1 (-e9059) | random.c           | comment contains url which has // | NO
| Rule 10.3 (-e9034)| random.c, sp_c64.c | cases where a value is narrowed | NO
| Rule 10.1 (-e9027)| sp_c64.c           | bit shift operations with signed type | NO
| Rule 16.3 (-e9090)| rsa.c              | switch fallthrough | YES
| Rule 14.3 (!e774) | random.c, sp_c64.c | allow always true 'if' to account for other build options | YES
| Rule 7.1 (!e9001) | random.c           | allow use of octal O_RDONLY | YES
| Rule 11.6 (!e923) | rsa.c              | allow cast of pointer to integer type with padding | YES
| Rule 10.4 (!e9029)| rsa.c              | allow missmatched types in RSA PSS | YES
| Rule 10.8 (!e9033)| sp_c64.c           | allow cast of mismatched types | YES
| Rule 1.3 (!e740)  | sp_c64.c           | allow cast of pointer | YES
| Rule 11.3 (!e9087)| random.c, sp_c64.c | allow cast of pointer | YES


### TODO

advisory warnings are still in progress
