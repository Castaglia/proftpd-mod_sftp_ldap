/*
 * ProFTPD: mod_sftp_ldap -- LDAP backend module for retrieving authorized keys
 * Copyright (c) 2010-2016 TJ Saunders
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, the respective copyright holders give permission
 * to link this program with OpenSSL, and distribute the resulting
 * executable, without including the source code for OpenSSL in the source
 * distribution.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_sftp_ldap.a $
 */

#include "mod_sftp_ldap.h"
#include "keys.h"

module sftp_ldap_module;

static const char *trace_channel = "ssh2";

static int ldapstore_verify_key_raw(pool *p, int nrow, char *ldap_data,
    size_t ldap_datalen, unsigned char *key_data, uint32_t key_datalen) {
  unsigned char *parsed_data = NULL;
  uint32_t parsed_datalen = 0;
  int res;

  res = sftp_ldap_keys_parse_raw(p, &ldap_data, &ldap_datalen, &parsed_data,
    &parsed_datalen);
  if (res < 0) {
    pr_trace_msg(trace_channel, 10,
      "unable to parse data (row %u) as raw key", nrow+1);
    return -1;
  }

  res = sftp_keys_compare_keys(p, key_data, key_datalen, parsed_data,
    parsed_datalen);
  if (res < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error comparing client-sent host key with LDAP data (row %u): %s",
      nrow+1, strerror(errno));

  } else if (res == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "client-sent host key does not match LDAP data (row %u)", nrow+1);
    res = -1;

  } else {
    res = 0;
  }

  return res;
}

static int ldapstore_verify_key_rfc4716(pool *p, int nrow, char *ldap_data,
    size_t ldap_datalen, unsigned char *key_data, uint32_t key_datalen) {
  unsigned char *parsed_data = NULL;
  uint32_t parsed_datalen = 0;
  int res;

  res = sftp_ldap_keys_parse_rfc4716(p, &ldap_data, &ldap_datalen, &parsed_data,
    &parsed_datalen);
  while (res == 0) {
    pr_signals_handle();

    res = sftp_keys_compare_keys(p, key_data, key_datalen, parsed_data,
      parsed_datalen);
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "error comparing client-sent key with LDAP data (row %u): %s",
        nrow+1, strerror(errno));

      parsed_data = NULL;
      parsed_datalen = 0;
      res = sftp_ldap_keys_parse_rfc4716(p, &ldap_data, &ldap_datalen,
        &parse_data, &parsed_datalen;);
      continue;

    } else if (res == FALSE) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "client-sent key does not match LDAP data (row %u)", nrow+1);

      parsed_data = NULL;
      parsed_datalen = 0;
      res = sftp_ldap_keys_parse_rfc4716(p, &ldap_data, &ldap_datalen,
        &parse_data, &parsed_datalen;);
      continue;
    }

    return 0;
  }

  return -1;
}

static int ldapstore_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_datalen) {
  register unsigned int i;
  pool *tmp_pool;
  cmdtable *ldap_cmdtab;
  cmd_rec *ldap_cmd;
  modret_t *ldap_res;
  array_header *ldap_keys;
  char **values;
  int res;

  /* Find the cmdtable for the ldap_ssh_publickey_lookup command. */
  ldap_cmdtab = pr_stash_get_symbol(PR_SYM_HOOK, "ldap_ssh_publickey_lookup",
    NULL, NULL);
  if (ldap_cmdtab == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "unable to find LDAP hook symbol 'ldap_ssh_publickey_lookup'");
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(store->keystore_pool);

  ldap_cmd = pr_cmd_alloc(tmp_pool, 1, user);

  ldap_res = pr_module_call(ldap_cmdtab->m, ldap_cmdtab->handler, ldap_cmd);
  if (ldap_res == NULL ||
      MODRET_ISERROR(ldap_res)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error performing LDAP search");
    destroy_pool(tmp_pool);

    errno = EPERM;
    return -1;
  }

  ldap_keys = (array_header *) ldap_res->data;

  if (ldap_keys->nelts == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "LDAP search returned zero results");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "LDAP search returned %d %s", ldap_keys->nelts,
      ldap_keys->nelts != 1 ? "keys" : "key");
  }

  values = (char **) ldap_keys->elts;
  for (i = 0; i < ldap_keys->nelts; i++) {
    char *ldap_data;
    size_t ldap_datalen;

    pr_signals_handle();

    ldap_data = values[i];
    ldap_datalen = strlen(values[i]);

    res = ldapstore_verify_key_rfc4716(p, i, ldap_data, ldap_datalen, key_data,
      key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10, "found matching RFC4716 public key "
        "(row %u) for user '%s'", i+1, user);
      destroy_pool(tmp_pool);
      return 0;
    }

    res = ldapstore_verify_key_raw(p, i, ldap_data, ldap_datalen, key_data,
      key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10,
        "found matching public key (row %u) for user '%s'", i+1, user);
      destroy_pool(tmp_pool);
      return 0;
    }
  }

  destroy_pool(tmp_pool);
  errno = ENOENT;
  return -1;
}

static int ldapstore_close(sftp_keystore_t *store) {
  /* Nothing to do here. */
  return 0;
}

static sftp_keystore_t *ldapstore_open(pool *parent_pool,
    int requested_key_type, const char *store_info, const char *user) {
  sftp_keystore_t *store;
  pool *ldapstore_pool;

  if (requested_key_type != SFTP_SSH2_USER_KEY_STORE) {
    errno = EPERM;
    return NULL;
  }

  ldapstore_pool = make_sub_pool(parent_pool);
  pr_pool_tag(ldapstore_pool, "SFTP LDAP-based Keystore Pool");

  store = pcalloc(ldapstore_pool, sizeof(sftp_keystore_t));
  store->keystore_pool = ldapstore_pool;
  store->store_ktypes = SFTP_SSH2_USER_KEY_STORE;
  store->verify_user_key = ldapstore_verify_user_key;
  store->store_close = ldapstore_close;

  return store;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sftpldap_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sftp_ldap.c", (const char *) event_data) == 0) {
    sftp_keystore_unregister_store("ldap", SFTP_SSH2_USER_KEY_STORE);
    pr_event_unregister(&sftp_ldap_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int sftpldap_init(void) {
  sftp_keystore_register_store("ldap", ldapstore_open,
    SFTP_SSH2_USER_KEY_STORE);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&sftp_ldap_module, "core.module-unload",
    sftpldap_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module sftp_ldap_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "sftp_ldap",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  sftpldap_init,

  /* Module child initialization function */
  NULL,

  /* Module version */
  MOD_SFTP_LDAP_VERSION
};
