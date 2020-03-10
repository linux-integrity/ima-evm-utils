check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += ima_hash.test sign_verify.test boot_aggregate.test

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean: distclean-keys
.PHONY: distclean-keys
distclean-keys:
	./gen-keys.sh clean
