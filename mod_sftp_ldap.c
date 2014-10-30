/*
 * ProFTPD: mod_sftp_ldap -- LDAP backend module for retrieving authorized keys
 *
 * Copyright (c) 2010 TJ Saunders
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
 */

#include "conf.h"
#include "privs.h"
#include "mod_sftp.h"

#define MOD_SFTP_LDAP_VERSION		"mod_sftp_ldap/0.1"

module sftp_ldap_module;

struct ldapstore_key {
  const char *subject;

  /* Key data */
  char *key_data;
  uint32_t key_datalen;
};

static const char *trace_channel = "ssh2";

/* Given a blob of bytes retrieved from an LDAP profile, read that blob as if
 * it were text, line by line.
 */
static char *ldapstore_getline(pool *p, char **blob, size_t *bloblen) {
  char linebuf[75], *line = "", *data;
  size_t datalen;

  data = *blob;
  datalen = *bloblen;

  if (data == NULL ||
      datalen == 0) {
    pr_trace_msg(trace_channel, 10,
      "reached end of data, no matching key found");
    errno = EOF;
    return NULL;
  }

  while (data != NULL && datalen > 0) {
    char *ptr;
    size_t delimlen, linelen;
    int have_line_continuation = FALSE;

    pr_signals_handle();

    if (datalen <= 2) {
      line = pstrcat(p, line, data, NULL);

      *blob = NULL;
      *bloblen = 0;

      return line;
    }

    /* Find the CRLF markers in the data. */
    ptr = strstr(data, "\r\n");
    if (ptr != NULL) {
      delimlen = 1;

    } else {
      ptr = strstr(data, "\n");
      if (ptr != NULL) {
        delimlen = 0;
      }
    }

    if (ptr == NULL) {
      /* Just return the rest of the data. */
      line = pstrcat(p, line, data, NULL);

      *blob = NULL;
      *bloblen = 0;

      return line;
    }

    linelen = (ptr - data + 1);

    if (linelen == 1) {
      data += (delimlen + 1);
      datalen -= (delimlen + 1);

      continue;
    }

    memcpy(linebuf, data, linelen);
    linebuf[linelen-1] = '\0';

    data += (linelen + delimlen);
    datalen -= (linelen + delimlen);

    /* Check for continued lines. */
    if (linelen >= 2 &&
        linebuf[linelen-2] == '\\') {
      linebuf[linelen-2] = '\0';
      have_line_continuation = TRUE;
    }

    line = pstrcat(p, line, linebuf, NULL);
    linelen = strlen(line);

    if (have_line_continuation) {
      continue;
    }

    ptr = strchr(line, ':');
    if (ptr != NULL) {
      unsigned int header_taglen, header_valuelen;

      /* We have a header.  Make sure the header tag is not longer than
       * the specified length of 64 bytes, and that the header value is
       * not longer than 1024 bytes.
       */
      header_taglen = ptr - line;
      if (header_taglen > 64) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
          "header tag too long (%u) in retrieved LDAP data", header_taglen);
        errno = EINVAL;
        return NULL;
      }

      /* Header value starts at 2 after the ':' (one for the mandatory
       * space character.
       */
      header_valuelen = linelen - (header_taglen + 2);
      if (header_valuelen > 1024) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
          "header value too long (%u) in retrieved LDAP data", header_valuelen);
        errno = EINVAL;
        return NULL;
      }
    }

    *blob = data;
    *bloblen = datalen;

    return line;
  }

  return NULL;
}

static struct ldapstore_key *ldapstore_get_key_raw(pool *p, char *blob) {
  char chunk[1024], *data = NULL;
  BIO *bio = NULL, *b64 = NULL, *bmem = NULL;
  int chunklen;
  long datalen = 0;
  size_t bloblen;
  struct ldapstore_key *key = NULL;

  bloblen = strlen(blob);
  bio = BIO_new(BIO_s_mem());

  if (BIO_write(bio, blob, bloblen) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error buffering base64 data: %s", sftp_crypto_get_errors());
    BIO_free_all(bio);

    errno = EINVAL;
    return NULL;
  }

  /* Add a base64 filter BIO, and read the data out, thus base64-decoding
   * the key.  Write the decoded data into another memory BIO.
   */
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  bmem = BIO_new(BIO_s_mem());

  memset(chunk, '\0', sizeof(chunk));
  chunklen = BIO_read(bio, chunk, sizeof(chunk));

  if (chunklen < 0 &&
      !BIO_should_retry(bio)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "unable to base64-decode data from LDAP directory: %s",
      sftp_crypto_get_errors());
    BIO_free_all(bio);
    BIO_free_all(bmem);

    errno = EPERM;
    return NULL;
  }

  while (chunklen > 0) {
    pr_signals_handle();

    if (BIO_write(bmem, chunk, chunklen) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "error writing to memory BIO: %s", sftp_crypto_get_errors());
      BIO_free_all(bio);
      BIO_free_all(bmem);

      errno = EPERM;
      return NULL;
    }

    memset(chunk, '\0', sizeof(chunk));
    chunklen = BIO_read(bio, chunk, sizeof(chunk));
  }

  datalen = BIO_get_mem_data(bmem, &data);

  if (data != NULL &&
      datalen > 0) {
    key = pcalloc(p, sizeof(struct ldapstore_key));
    key->key_data = pcalloc(p, datalen + 1);
    key->key_datalen = datalen;
    memcpy(key->key_data, data, datalen);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error base64-decoding raw key data from LDAP directory");
  }

  BIO_free_all(bio);
  bio = NULL;

  BIO_free_all(bmem);
  return key;
}

static struct ldapstore_key *ldapstore_get_key_rfc4716(pool *p, char *blob) {
  char *line;
  BIO *bio = NULL;
  size_t bloblen, begin_markerlen = 0, end_markerlen = 0;
  struct ldapstore_key *key = NULL;

  bloblen = strlen(blob);

  line = ldapstore_getline(p, &blob, &bloblen);
  while (line == NULL &&
         errno == EINVAL) {
    pr_signals_handle();
    line = ldapstore_getline(p, &blob, &bloblen);
  }

  if (line == NULL) {
    return NULL;
  }

  begin_markerlen = strlen(SFTP_SSH2_PUBKEY_BEGIN_MARKER);
  end_markerlen = strlen(SFTP_SSH2_PUBKEY_END_MARKER);

  while (line != NULL) {
    pr_signals_handle();

    if (key == NULL &&
        strncmp(line, SFTP_SSH2_PUBKEY_BEGIN_MARKER,
          begin_markerlen + 1) == 0) {
      key = pcalloc(p, sizeof(struct ldapstore_key));
      bio = BIO_new(BIO_s_mem());

    } else if (key != NULL &&
               strncmp(line, SFTP_SSH2_PUBKEY_END_MARKER,
                 end_markerlen + 1) == 0) {
      if (bio != NULL) {
        char chunk[1024], *data = NULL;
        BIO *b64 = NULL, *bmem = NULL;
        int chunklen;
        long datalen = 0;

        /* Add a base64 filter BIO, and read the data out, thus base64-decoding
         * the key.  Write the decoded data into another memory BIO.
         */
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        bmem = BIO_new(BIO_s_mem());

        memset(chunk, '\0', sizeof(chunk));
        chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));

        if (chunklen < 0 &&
            !BIO_should_retry(bio)) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
            "unable to base64-decode RFC4716 key data from LDAP: %s",
          sftp_crypto_get_errors());
          BIO_free_all(bio);
          BIO_free_all(bmem);

          errno = EPERM;
          return NULL;
        }

        while (chunklen > 0) {
          pr_signals_handle();

          if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
              "error writing to memory BIO: %s", sftp_crypto_get_errors());
            BIO_free_all(bio);
            BIO_free_all(bmem);

            errno = EPERM;
            return NULL;
          }

          memset(chunk, '\0', sizeof(chunk));
          chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
        }

        datalen = BIO_get_mem_data(bmem, &data);

        if (data != NULL &&
            datalen > 0) {
          key = pcalloc(p, sizeof(struct ldapstore_key));
          key->key_data = pcalloc(p, datalen + 1);
          key->key_datalen = datalen;
          memcpy(key->key_data, data, datalen);

        } else {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
            "error base64-decoding RFC4716 key data from LDAP");
        }

        BIO_free_all(bio);
        bio = NULL;

        BIO_free_all(bmem);
      }

      break;

    } else {
      if (key) {
        if (strstr(line, ": ") != NULL) {
          if (strncasecmp(line, "Subject: ", 9) == 0) {
            key->subject = pstrdup(p, line + 9);
          }

        } else {
          if (BIO_write(bio, line, strlen(line)) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
              "error buffering base64 data");
          }
        }
      }
    }

    line = ldapstore_getline(p, &blob, &bloblen);
    while (line == NULL &&
           errno == EINVAL) {
      pr_signals_handle();
      line = ldapstore_getline(p, &blob, &bloblen);
    }
  }

  return key;
}

static int ldapstore_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_datalen) {
  register unsigned int i;
  struct ldapstore_key *key;
  pool *tmp_pool;
  cmdtable *ldap_cmdtab;
  cmd_rec *ldap_cmd;
  modret_t *ldap_res;
  array_header *ldap_data;
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

  ldap_data = (array_header *) ldap_res->data;

  if (ldap_data->nelts == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "LDAP search returned zero results");
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "LDAP search returned %d %s", ldap_data->nelts,
      ldap_data->nelts != 1 ? "keys" : "key");
  }

  values = (char **) ldap_data->elts;
  for (i = 0; i < ldap_data->nelts; i++) {
    pr_signals_handle();

    key = ldapstore_get_key_raw(p, values[i]);
    if (key == NULL) {
      key = ldapstore_get_key_rfc4716(p, values[i]);
    }

    if (key == NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "error obtaining SSH2 public key from LDAP data (key %u)", i+1);
      continue;
    }

    res = sftp_keys_compare_keys(p, key_data, key_datalen,
      (unsigned char *) key->key_data, key->key_datalen);
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "error comparing client-sent user key with LDAP data (key %u): %s",
        i+1, strerror(errno));
      continue;

    } else if (res == FALSE) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "client-sent user key does not match LDAP data (key %u)", i+1);
      continue;
    }

    pr_trace_msg(trace_channel, 10, "found matching public key (row %u) for "
      "user '%s' using LDAP search", i+1, user);
    destroy_pool(tmp_pool);
    return 0;
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
