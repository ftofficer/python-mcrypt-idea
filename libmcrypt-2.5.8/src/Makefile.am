## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = ciphertest aestest ideatest

ciphertest_SOURCES = cipher_test.c
ciphertest_LDADD = ../lib/libmcrypt.la $(LIBLTDL) 

aestest_SOURCES = aes_test.c
aestest_LDADD = ../lib/libmcrypt.la $(LIBLTDL) 

ideatest_SOURCES = idea_test.c
ideatest_LDADD = ../lib/libmcrypt.la $(LIBLTDL) 

TESTS = ciphertest aestest ideatest

