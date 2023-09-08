/*
 * ProFTPD: mod_sftp_ldap keys
 * Copyright (c) 2010-2023 TJ Saunders
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

#define SFTP_LDAP_BUFSZ				1024

#define SFTP_LDAP_KEY_BEGIN_MARKER_LEN		31
#define SFTP_LDAP_KEY_END_MARKER_LEN		29

/* Given a blob of bytes retrieved from a single row, read that blob as if
 * it were text, line by line.
 */
static char *get_line(pool *p, char **blob, size_t *bloblen) {
  char linebuf[SFTP_LDAP_BUFSZ], *line = "", *data = NULL;
  size_t datalen;

  data = *blob;
  datalen = *bloblen;

  if (data == NULL ||
      datalen == 0) {
    errno = EOF;
    return NULL;
  }

  while (data != NULL && datalen > 0) {
    char *ptr = NULL;
    size_t delimlen = 0, linelen = 0;
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

    if (have_line_continuation == TRUE) {
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
  int chunklen, res;
  long datalen = 0;
  char *ptr;

  if (p == NULL ||
      blob == NULL ||
      bloblen == NULL ||
      key_data == NULL ||
      key_datalen == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* First we need to check for any leading/trailing SSH-isms in the key, i.e.
   * an "ssh-rsa", "ssh-dss", or "ecdsa-sha2-nistp*" prefix.  Fortunately
   * the prefix, and the trailing suffix, are separated from the key material
   * with spaces.
   */
  ptr = strchr(*blob, ' ');
  if (ptr != NULL) {
    size_t prefix_len;

    /* Advance the blob pointer past the prefix. */
    prefix_len = (ptr + 1) - *blob;
    (*bloblen) -= prefix_len;
    (*blob) += prefix_len;
  }

  ptr = strrchr(*blob, ' ');
  if (ptr != NULL) {
    size_t suffix_len;

    /* "Trim" off the suffix by truncating the bloblen appropriately. */
    suffix_len = strlen(ptr);
    (*bloblen) -= suffix_len;
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
    res = 0;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
      "error base64-decoding key data from LDAP directory");
    errno = ENOENT;
    res = -1;
  }

  BIO_free_all(bio);
  bio = NULL;

  BIO_free_all(bmem);
  return res;
}

/* Note: When iterating backwards, be sure to ignore/skip over any potential
 * end marker.
 */
static void find_key_start(char **line, size_t *linelen) {
  register unsigned int i;

  /* Do NOT examine the end marker. */
  if (*linelen >= SFTP_LDAP_KEY_END_MARKER_LEN) {
    size_t datalen;

    datalen = *linelen - SFTP_LDAP_KEY_END_MARKER_LEN;
    if (strncmp(*line + datalen, SFTP_SSH2_PUBKEY_END_MARKER, SFTP_LDAP_KEY_END_MARKER_LEN) == 0) {
      i = datalen;

    } else {
      i = *linelen;
    }

  } else {
    i = *linelen;
  }

  while (i-- > 0) {
    char ch;

    pr_signals_handle();

    ch = (*line)[i];

    if (('a' <= ch && ch <= 'z') ||
        ('A' <= ch && ch <= 'Z') ||
        ('0' <= ch && ch <= '9') ||
        ch == '+' ||
        ch == '/' ||
        ch == '=') {
      continue;
    }

    /* The start of the line, then, is the next character AFTER this one. */
    *line = &((*line)[i+1]);
    *linelen = *linelen - i - 1;
    break;
  }
}

int sftp_ldap_keys_parse_rfc4716(pool *p, char **blob, size_t *bloblen,
    unsigned char **key_data, uint32_t *key_datalen, pr_table_t *headers) {
  char *line;
  BIO *bio = NULL;
  int had_key_data = FALSE, res = -1;

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

  while (line != NULL) {
    size_t linelen;

    pr_signals_handle();

    linelen = strlen(line);

    if (bio == NULL &&
        strncmp(line, SFTP_SSH2_PUBKEY_BEGIN_MARKER, SFTP_LDAP_KEY_BEGIN_MARKER_LEN) == 0) {
      bio = BIO_new(BIO_s_mem());
      linelen -= SFTP_LDAP_KEY_BEGIN_MARKER_LEN;
      line += SFTP_LDAP_KEY_BEGIN_MARKER_LEN;

      had_key_data = TRUE;
    }

    if (bio != NULL &&
        linelen >= SFTP_LDAP_KEY_END_MARKER_LEN &&
        strncmp(line, SFTP_SSH2_PUBKEY_END_MARKER, SFTP_LDAP_KEY_END_MARKER_LEN) == 0) {
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
        res = 0;

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
          "error base64-decoding RFC4716 key data from LDAP directory");
        errno = ENOENT;
        res = -1;
      }

      BIO_free_all(bio);
      bio = NULL;

      BIO_free_all(bmem);
      break;
    }

    if (bio != NULL &&
        linelen > 0) {
      size_t chunklen;

      /* Watch out for any headers in the key data; we cannot handle those
       * here.  However, if we simply bail, it makes things difficult for the
       * admin wishing to use the keys, as user authentication will fail.
       *
       * Thus we try some heuristics to avoid/skip the headers.  The key data
       * in which we are interested is base64-encoded.  We thus iterate from
       * the end of the line, looking for any non-base64 characters.  If found,
       * we ignore them.
       */
      find_key_start(&line, &linelen);

      chunklen = linelen;

      /* Do NOT consume the end marker. */
      if (linelen >= SFTP_LDAP_KEY_END_MARKER_LEN) {
        size_t datalen;

        datalen = linelen - SFTP_LDAP_KEY_END_MARKER_LEN;
        if (strncmp(line + datalen, SFTP_SSH2_PUBKEY_END_MARKER, SFTP_LDAP_KEY_END_MARKER_LEN) == 0) {
          /* Truncate the data to be written to the bio to not include the
           * end marker.
           */
          chunklen -= SFTP_LDAP_KEY_END_MARKER_LEN;
        }
      }

      if (chunklen > 0) {
        if (BIO_write(bio, line, chunklen) < 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_LDAP_VERSION,
            "error buffering base64 data: %s", sftp_crypto_get_errors());
        }

        linelen -= chunklen;
        line += chunklen;
      }

    } else {
      /* Consider this line consumed. */
      linelen = 0;
    }

    /* Get the next line, but only if we're done with this one. */
    if (linelen == 0) {
      line = get_line(p, blob, bloblen);
      while (line == NULL &&
             errno == EINVAL) {
        pr_signals_handle();
        line = get_line(p, blob, bloblen);
      }
    }
  }

  /* Provide a default errno value if necessary. */
  if (had_key_data == FALSE &&
      res < 0) {
    errno = ENOENT;
  }

  return res;
}
