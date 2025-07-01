check_SCRIPTS =
if KERNEL_TESTS
TESTS = $(check_SCRIPTS)
endif

check_SCRIPTS += fsverity.test portable_signatures.test mmap_check.test \
		 evm_hmac.test non_action_rule_flags.test

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
	shellcheck ../functions.sh functions_kernel.sh $(check_SCRIPTS)

.PHONY: distclean-keys shellcheck
distclean-keys:
	../gen-keys.sh clean
