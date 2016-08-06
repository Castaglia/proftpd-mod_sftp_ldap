/*
 * ProFTPD - mod_sftp_ldap testsuite
 * Copyright (c) 2016 TJ Saunders <tj@castaglia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

/* Key-parsing tests. */

#include "tests.h"

static pool *p = NULL;

struct ldapstore_key {
  unsigned char *key_data;
  uint32_t key_datalen;
};

static void set_up(void) {
  if (p == NULL) {
    sftp_pool = p = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("ssh2", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("ssh2", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    sftp_pool = p = NULL;
  } 
}

/* Notes: we are targetting the ldapstore_verify_user_key() function.
 * Alternatively, we could target the following directly:
 *   ldapstore_verify_key_rfc4716()
 *   ldapstore_verify_key_raw()
 *
 * Or, even better:
 *   ldapstore_get_key_rfc4716()
 *   ldapstore_get_key_raw()
 *
 * This latter approach would require having struct ldapstore_key defined
 * in an accessible place, or redefined in stubs.  OR split them out
 * into keys.[ch] files -- easier testing.
 */

START_TEST (raw_key_test) {
}
END_TEST

START_TEST (rfc4716_key_test) {
  /* One key WITH Comment/Subject headers (fail), one key without */
}
END_TEST

Suite *tests_get_keys_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("keys");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, raw_key_test);
  tcase_add_test(testcase, rfc4716_key_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
