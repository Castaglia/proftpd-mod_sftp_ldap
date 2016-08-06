/*
 * ProFTPD: mod_sftp_ldap keys
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
 */

#include "keys.h"

#define SFTP_LDAP_BUFSZ			1024

/* Given a blob of bytes retrieved from a single row, read that blob as if
 * it were text, line by line.
 */
static char *get_line(pool *p, char **blob, size_t *bloblen) {
  char linebuf[SFTP_LDAP_BUFSZ], *line = "", *data;
  size_t datalen;

  data = *blob;
  datalen = *bloblen;

  if (data == NULL ||
      datalen == 0) {
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

    /* Watch out for lines larger than our buffer. */
    if (linelen > sizeof(linebuf)) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "line of key data (%lu bytes) exceeds buffer size, truncating; "
        "this WILL cause authentication failures", (unsigned long) linelen);
      linelen = sizeof(linebuf);
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

int sftp_ldap_keys_parse_raw(pool *p, char **blob, size_t *bloblen,
    unsigned char **key_data, uint32_t *key_datalen) {
  char chunk[SFTP_LDAP_BUFSZ], *data = NULL;
  BIO *bio = NULL, *b64 = NULL, *bmem = NULL;
  int chunklen;
  long datalen = 0;

  if (p == NULL ||
      blob == NULL ||
      bloblen == NULL ||
      key_data == NULL ||
      key_datalen == NULL) {
    errno = EINVAL;
    return -1;
  }

  bio = BIO_new(BIO_s_mem());

  if (BIO_write(bio, (void *) *blob, *bloblen) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error buffering base64 data: %s", sftp_crypto_get_errors());
  }

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
      "unable to base64-decode data from LDAP directory: %s",
      sftp_crypto_get_errors());
    BIO_free_all(bio);
    BIO_free_all(bmem);

    errno = EPERM;
    return -1;
  }

  while (chunklen > 0) {
    pr_signals_handle();

    if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
        "error writing to memory BIO: %s", sftp_crypto_get_errors());
      BIO_free_all(bio);
      BIO_free_all(bmem);

      errno = EPERM;
      return -1;
    }

    memset(chunk, '\0', sizeof(chunk));
    chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
  }

  datalen = BIO_get_mem_data(bmem, &data);

  if (data != NULL &&
      datalen > 0) {
    *key_datalen = datalen;
    *key_data = palloc(p, datalen + 1);
    (*key_data)[datalen] = '\0';
    memcpy(*key_data, data, datalen);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error base64-decoding key data from LDAP directory");
  }

  BIO_free_all(bio);
  bio = NULL;

  BIO_free_all(bmem);
  return 0;
}

int sftp_ldap_keys_parse_rfc4716(pool *p, char **blob, size_t *bloblen,
    unsigned char **key_data, uint32_t *key_datalen) {
  char *line;
  BIO *bio = NULL;
  size_t begin_markerlen = 0, end_markerlen = 0;

  if (p == NULL ||
      blob == NULL ||
      bloblen == NULL ||
      key_data == NULL ||
      key_datalen == NULL) {
    errno = EINVAL;
    return -1;
  }

  line = get_line(p, blob, bloblen);
  while (line == NULL &&
         errno == EINVAL) {
    pr_signals_handle();
    line = get_line(p, blob, bloblen);
  }

  if (line == NULL) {
    return -1;
  }

  begin_markerlen = strlen(SFTP_SSH2_PUBKEY_BEGIN_MARKER);
  end_markerlen = strlen(SFTP_SSH2_PUBKEY_END_MARKER);

  while (line != NULL) {
    pr_signals_handle();

    if (bio == NULL &&
        strncmp(line, SFTP_SSH2_PUBKEY_BEGIN_MARKER, begin_markerlen) == 0) {
      bio = BIO_new(BIO_s_mem());

    } else if (strncmp(line, SFTP_SSH2_PUBKEY_END_MARKER, end_markerlen) == 0) {
      if (bio != NULL) {
        char chunk[SFTP_LDAP_BUFSZ], *data = NULL;
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
            "unable to base64-decode RFC4716 key data from database: %s",
          sftp_crypto_get_errors());
          BIO_free_all(bio);
          BIO_free_all(bmem);

          errno = EPERM;
          return -1;
        }

        while (chunklen > 0) {
          pr_signals_handle();

          if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
              "error writing to memory BIO: %s", sftp_crypto_get_errors());
            BIO_free_all(bio);
            BIO_free_all(bmem);

            errno = EPERM;
            return -1;
          }

          memset(chunk, '\0', sizeof(chunk));
          chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
        }

        datalen = BIO_get_mem_data(bmem, &data);

        if (data != NULL &&
            datalen > 0) {
          *key_datalen = datalen;
          *key_data = palloc(p, datalen + 1);
          (*key_data)[datalen] = '\0';
          memcpy(*key_data, data, datalen);

        } else {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
            "error base64-decoding RFC4716 key data from LDAP directory");
        }

        BIO_free_all(bio);
        bio = NULL;

        BIO_free_all(bmem);
      }

      break;

    } else {
      if (BIO_write(bio, line, strlen(line)) < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
          "error buffering base64 data: %s", sftp_crypto_get_errors());
      }
    }

    line = get_line(p, blob, bloblen);
    while (line == NULL &&
           errno == EINVAL) {
      pr_signals_handle();
      line = get_line(p, blob, bloblen);
    }
  }

  return 0;
}
