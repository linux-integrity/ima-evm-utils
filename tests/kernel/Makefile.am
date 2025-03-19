check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += fsverity.test portable_signatures.test mmap_check.test \
		 evm_hmac.test

check_PROGRAMS := test_mmap

.PHONY: check_logs
check_logs:
	@for log in $(TEST_LOGS); do \
	   echo -e "\n***" $$log "***" ; \
	   cat $$log ; \
	done

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean-local: distclean-keys

shellcheck:
	shellcheck functions_kernel.sh $(check_SCRIPTS)

.PHONY: distclean-keys shellcheck
distclean-keys:
	../gen-keys.sh clean
