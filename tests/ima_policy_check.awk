#! /usr/bin/gawk -f
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023 Roberto Sassu <roberto.sassu@huawei.com>
#
# Check a new rule against the loaded IMA policy.
#
# Documentation/ABI/testing/ima_policy (Linux kernel)
# base:	[[func=] [mask=] [fsmagic=] [fsuuid=] [fsname=]
#	[uid=] [euid=] [gid=] [egid=]
#	[fowner=] [fgroup=]]
# lsm:	[[subj_user=] [subj_role=] [subj_type=]
#	[obj_user=] [obj_role=] [obj_type=]]
# option:	[digest_type=] [template=] [permit_directio]
#		[appraise_type=] [appraise_flag=]
#		[appraise_algos=] [keyrings=]
#
# Rules don't overlap if their actions are unrelated (cannot be matched without
# dont_) and there is no combination of appraise with another do action (e.g.
# measure, audit, hash). The second condition is due to the fact that appraise
# might still forbid other actions expected to be performed by a test that did
# not setup appraisal. Checking appraise for new rules is not sufficient,
# because that rule could be added anyway. By checking existing rules as well,
# a warning will be displayed when tests inserting rules with other do actions
# are reexecuted.
#
# Also, rules don't overlap if both include the same policy keyword(s) (in base
# or lsm, except func), at least one, with a different value. Different func
# values don't imply non-overlap, due to the fact that a test command might
# cause the execution of multiple hooks (e.g. FILE_CHECK in addition to
# MMAP_CHECK). Despite one test is willing to test a particular hook, this could
# have side effects on other tests (e.g. one test sets: appraise func=MMAP_CHECK
# and another: measure func=FILE_CHECK; the second test might see an unexpected
# measurement due to the first test being executed; or the second test cannot
# unexpectedly do mmap).
#
# Currently, the < > operators are not supported and overlapping is asserted
# even if intervals are disjoint. If supported, non-overlapping conditions could
# be found. With the ^ modifier, no disjoint intervals can be found. Overlapping
# is always reported.
#
# Rule equivalence is determined by checking each key/value pair, regardless of
# their order. However, the action must always be at the beginning of the rules.
# Rules with aliases are considered equivalent to those with their source (e.g.
# rules with PATH_CHECK and FILE_MMAP are considered as equivalent to rules with
# FILE_CHECK and MMAP_CHECK).
#
# Return a bit mask with the following values:
# - 1: invalid new rule;
# - 2: overlap of the new rule with an existing rule in the IMA policy;
# - 4: new rule exists in the IMA policy.

BEGIN {
	# Policy definitions.
	actions_str="measure dont_measure appraise dont_appraise audit hash dont_hash"
	split(actions_str, actions_array);
	keywords_str="func mask fsmagic fsuuid fsname uid euid gid egid fowner fgroup subj_user subj_role subj_type obj_user obj_role obj_type";
	split(keywords_str, keywords_array);
	options_str="digest_type template permit_directio appraise_type appraise_flag appraise_algos keyrings";
	split(options_str, options_array);

	# Key types.
	key_type_unknown=0;
	key_type_action=1;
	key_type_keyword=2;
	key_type_option=3;

	# Result values.
	ret_invalid_rule=1;
	ret_rule_overlap=2;
	ret_same_rule_exists=4;

	for (action_idx in actions_array)
		key_types[actions_array[action_idx]]=key_type_action;
	for (keyword_idx in keywords_array)
		key_types[keywords_array[keyword_idx]]=key_type_keyword;
	for (option_idx in options_array)
		key_types[options_array[option_idx]]=key_type_option;

	new_rule=1;
	result=0;
}
{
	# Delete arrays from previous rule.
	if (!new_rule) {
		delete current_rule_array;
		delete current_rule_operator_array;
	}

	# Check empty rules.
	if (!length($0)) {
		if (new_rule) {
			result=or(result, ret_invalid_rule);
			exit;
		}
		next;
	}

	for (i=1; i<=NF; i++) {
		# Parse key/value pair.
		split($i, key_value_array, /[=,>,<]/, separator_array);
		key=key_value_array[1];
		value=key_value_array[2];

		if (key == "func") {
			# Normalize values of IMA hooks to what IMA will print.
			if (value == "FILE_MMAP")
				value="MMAP_CHECK";
			else if (value == "PATH_CHECK")
				value="FILE_CHECK";
		}

		# Basic validity check (not necessary in general for the IMA policy, but useful to find typos in the tests).
		if (key_types[key] == key_type_unknown ||
		    (i == 1 && key_types[key] != key_type_action)) {
			result=or(result, ret_invalid_rule);
			exit;
		}

		# Store key/value pair and operator into an array.
		if (new_rule) {
			new_rule_array[key]=value;
			new_rule_operator_array[key]=separator_array[1];
		} else {
			current_rule_array[key]=value;
			current_rule_operator_array[key]=separator_array[1];
		}

		# Store original action and action without dont_.
		if (i == 1) {
			if (new_rule) {
				new_rule_action=key;
				new_rule_action_sub=key;
				gsub(/dont_/, "", new_rule_action_sub);
			} else {
				current_rule_action=key;
				current_rule_action_sub=key;
				gsub(/dont_/, "", current_rule_action_sub);
			}
		}
	}

	# Go to the next line, to compare the new rule with rules in the IMA policy.
	if (new_rule) {
		new_rule=0;
		next;
	}

	# No overlap by action (unrelated rules and no combination appraise - <do action>), new rule safe to add to the IMA policy.
	if (current_rule_action_sub != new_rule_action_sub &&
	    (current_rule_action != "appraise" || new_rule_action ~ /^dont_/) &&
	    (new_rule_action != "appraise" || current_rule_action ~ /^dont_/))
		next;

	same_rule=1;
	overlap_rule=1;

	for (key in key_types) {
		if (!(key in new_rule_array)) {
			# Key in current rule but not in new rule.
			if (key in current_rule_array)
				same_rule=0;
			# Key not in new rule and not in current rule.
			continue;
		}

		if (!(key in current_rule_array)) {
			# Key in new rule but not in current rule.
			if (key in new_rule_array)
				same_rule=0;
			# Key not in current rule and not in new rule.
			continue;
		}

		# Same value and operator.
		if (new_rule_array[key] == current_rule_array[key] &&
		    new_rule_operator_array[key] == current_rule_operator_array[key])
			continue;

		# Different value and/or operator.
		same_rule=0;

		# Not a policy keyword, not useful to determine overlap.
		if (key_types[key] != key_type_keyword)
			continue;

		# > < operators are not supported, cannot determine overlap.
		if (new_rule_operator_array[key] != "=" || current_rule_operator_array[key] != "=")
			continue;

		# ^ modifier does not make disjoint sets, cannot determine overlap.
		if (new_rule_array[key] ~ /^\^/ || current_rule_array[key] ~ /^\^/)
			continue;

		# One test command can invoke multiple hooks, cannot determine overlap from func.
		if (key == "func")
			continue;

		# No overlap by policy keyword, new rule safe to add to the IMA policy.
		overlap_rule=0;
		next;
	}

	if (same_rule)
		result=or(result, ret_same_rule_exists);
	else if (overlap_rule)
		result=or(result, ret_rule_overlap);
}
END {
	exit result;
}
