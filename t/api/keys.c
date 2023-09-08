/*
 * ProFTPD - mod_sftp_ldap testsuite
 * Copyright (c) 2016-2023 TJ Saunders <tj@castaglia.org>
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
#include "keys.h"

static pool *p = NULL;

static const char *raw_key = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7jGx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00ydqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84uO6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMmef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPkByq2pv4VBo953gK7f1AQ== tj@Imp.local";

static const char *rfc4716_single_line_key =
  "---- BEGIN SSH2 PUBLIC KEY ----"
  "AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7j"
  "Gx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00y"
  "dqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84u"
  "O6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMm"
  "ef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPk"
  "Byq2pv4VBo953gK7f1AQ=="
  "---- END SSH2 PUBLIC KEY ----";

static const char *rfc4716_single_line_key_with_comment =
  "---- BEGIN SSH2 PUBLIC KEY ----"
  "Comment: \"2048-bit RSA, converted from OpenSSH by tj@Imp.local\""
  "AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7j"
  "Gx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00y"
  "dqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84u"
  "O6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMm"
  "ef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPk"
  "Byq2pv4VBo953gK7f1AQ=="
  "---- END SSH2 PUBLIC KEY ----";

static const char *rfc4716_single_line_key_with_xtag =
  "---- BEGIN SSH2 PUBLIC KEY ----"
  "X-Tag: Foo Bar"
  "AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7j"
  "Gx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00y"
  "dqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84u"
  "O6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMm"
  "ef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPk"
  "Byq2pv4VBo953gK7f1AQ=="
  "---- END SSH2 PUBLIC KEY ----";

static const char *rfc4716_multi_line_key =
  "---- BEGIN SSH2 PUBLIC KEY ----\n"
  "AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7j\n"
  "Gx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00y\n"
  "dqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84u\n"
  "O6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMm\n"
  "ef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPk\n"
  "Byq2pv4VBo953gK7f1AQ==\n"
  "---- END SSH2 PUBLIC KEY ----\n";

static const char *rfc4716_multi_line_key_with_comment =
  "---- BEGIN SSH2 PUBLIC KEY ----\n"
  "Comment: \"2048-bit RSA, converted from OpenSSH by tj@Imp.local\"\n"
  "AAAAB3NzaC1yc2EAAAABIwAAAQEAzJ1CLwnVP9mUa8uyM+XBzxLxsRvGz4cS59aPTgdw7j\n"
  "Gx1jCvC9ya400x7ej5Q4ubwlAAPblXzG5GYv2ROmYQ1DIjrhmR/61tDKUvAAZIgtvLZ00y\n"
  "dqqpq5lG4ubVJ4gW6sxbPfq/X12kV1gxGsFLUJCgoYInZGyIONrnvmQjFIfIx+mQXaK84u\n"
  "O6w0CT6KhRWgonajMrlO6P8O7qr80rFmOZsBNIMooyYrGTaMyxVsQK2SY+VKbXWFC+2HMm\n"
  "ef62n+02ohAOBKtOsSOn8HE2wi7yMA0g8jRTd8kZcWBIkAhizPvl8pqG1F0DCmLn00rhPk\n"
  "Byq2pv4VBo953gK7f1AQ==\n"
  "---- END SSH2 PUBLIC KEY ----\n";

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

START_TEST (keys_parse_raw_invalid_params_test) {
  int res;
  char *blob = NULL;
  size_t bloblen = 0;
  unsigned char *key_data = NULL;

  res = sftp_ldap_keys_parse_raw(NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_raw(p, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null blob");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_raw(p, &blob, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bloblen");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_raw(p, &blob, &bloblen, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null key data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_raw(p, &blob, &bloblen, &key_data, NULL);
  fail_unless(res < 0, "Failed to handle null key datalen");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (keys_parse_raw_single_line_test) {
  int res;
  char *blob;
  size_t bloblen;
  unsigned char *key_data = NULL;
  uint32_t key_datalen = 0;

  blob = "foo\n";
  bloblen = strlen(blob);
  res = sftp_ldap_keys_parse_raw(p, &blob, &bloblen, &key_data, &key_datalen);
  fail_unless(res < 0, "Failed to handle invalid raw key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  blob = pstrdup(p, raw_key);
  bloblen = strlen(raw_key);
  key_data = NULL;
  key_datalen = 0;
  res = sftp_ldap_keys_parse_raw(p, &blob, &bloblen, &key_data, &key_datalen);
  fail_unless(res == 0, "Failed to handle valid raw key: %s", strerror(errno));
}
END_TEST

START_TEST (keys_parse_rfc4716_invalid_params_test) {
  int res;
  char *blob = NULL;
  size_t bloblen = 0;
  unsigned char *key_data = NULL;

  res = sftp_ldap_keys_parse_rfc4716(NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_rfc4716(p, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null blob");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_rfc4716(p, &blob, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bloblen");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null key data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null key datalen");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (keys_parse_rfc4716_single_line_test) {
  int res;
  char *blob;
  size_t bloblen;
  unsigned char *key_data = NULL;
  uint32_t key_datalen = 0;
  pr_table_t *headers = NULL;

  mark_point();
  blob = "foo\n";
  bloblen = strlen(blob);
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, NULL);
  fail_unless(res < 0, "Failed to handle invalid RFC 4716 key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  blob = pstrdup(p, rfc4716_single_line_key_with_comment);
  bloblen = strlen(rfc4716_single_line_key_with_comment);
  key_data = NULL;
  key_datalen = 0;
  headers = pr_table_nalloc(p, 0, 1);
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, headers);
  fail_unless(res == 0,
    "Failed to handle RFC 4716 key with Comment header: %s", strerror(errno));

  mark_point();
  blob = pstrdup(p, rfc4716_single_line_key_with_xtag);
  bloblen = strlen(rfc4716_single_line_key_with_xtag);
  key_data = NULL;
  key_datalen = 0;
  headers = pr_table_nalloc(p, 0, 1);
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, headers);
  fail_unless(res == 0,
    "Failed to handle RFC 4716 key with X-Tag header: %s", strerror(errno));

  mark_point();
  blob = pstrdup(p, rfc4716_single_line_key);
  bloblen = strlen(rfc4716_single_line_key);
  key_data = NULL;
  key_datalen = 0;
  headers = pr_table_nalloc(p, 0, 1);
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, headers);
  fail_unless(res == 0, "Failed to handle valid RFC 4716 key: %s",
    strerror(errno));
}
END_TEST

START_TEST (keys_parse_rfc4716_multi_line_test) {
  int res;
  char *blob;
  size_t bloblen;
  unsigned char *key_data = NULL;
  uint32_t key_datalen = 0;

  blob = "foo\n";
  bloblen = strlen(blob);
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, NULL);
  fail_unless(res < 0, "Failed to handle invalid RFC 4716 key");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  blob = pstrdup(p, rfc4716_multi_line_key_with_comment);
  bloblen = strlen(rfc4716_multi_line_key_with_comment);
  key_data = NULL;
  key_datalen = 0;
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, NULL);
  fail_unless(res == 0,
    "Failed to handle RFC 4716 key with Comment header: %s", strerror(errno));

  blob = pstrdup(p, rfc4716_multi_line_key);
  bloblen = strlen(rfc4716_multi_line_key);
  key_data = NULL;
  key_datalen = 0;
  res = sftp_ldap_keys_parse_rfc4716(p, &blob, &bloblen, &key_data,
    &key_datalen, NULL);
  fail_unless(res == 0, "Failed to handle valid RFC 4716 key: %s",
    strerror(errno));
}
END_TEST

Suite *tests_get_keys_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("keys");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, keys_parse_raw_invalid_params_test);
  tcase_add_test(testcase, keys_parse_raw_single_line_test);
  tcase_add_test(testcase, keys_parse_rfc4716_invalid_params_test);
  tcase_add_test(testcase, keys_parse_rfc4716_single_line_test);
  tcase_add_test(testcase, keys_parse_rfc4716_multi_line_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
