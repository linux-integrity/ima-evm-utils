check_SCRIPTS =
TESTS = $(check_SCRIPTS)

SUBDIRS = .

if KERNEL_TESTS
SUBDIRS += kernel
endif

check_SCRIPTS += ima_hash.test sign_verify.test boot_aggregate.test \
		 ima_policy_check.test

.PHONY: check_logs
check_logs:
	@for log in $(TEST_LOGS); do \
	   echo -e "\n***" $$log "***" ; \
	   case $$log in \
	   ima_hash.log | sign_verify.log ) \
	       tail -3 $$log ; \
	       grep "skipped" $$log && grep "skipped" $$log | wc -l ;; \
	   *) \
	       cat $$log ;; \
	   esac ; \
	done
	make -C kernel $@

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean-local: distclean-keys

shellcheck:
	shellcheck \
		functions.sh gen-keys.sh install-fsverity.sh \
		install-mount-idmapped.sh install-openssl3.sh \
		install-swtpm.sh install-tss.sh softhsm_setup \
		$(check_SCRIPTS)
	make -C kernel $@

.PHONY: distclean-keys shellcheck
distclean-keys:
	./gen-keys.sh clean
