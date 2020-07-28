/*
 * Copyright (c) 2014-2020 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if WANT_PDNS_DNSDB || WANT_PDNS_DNSDB2

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>

#include "defs.h"
#include "pdns.h"
#include "pdns_dnsdb.h"
#include "time.h"
#include "globals.h"

/* forwards. */

static const char *dnsdb_setval(const char *, const char *);
static const char *dnsdb_ready(void);
static void dnsdb_destroy(void);
static char *dnsdb_url(const char *, char *, qdesc_ct, pdns_fence_ct);
static void dnsdb_auth(fetch_t);
static const char *dnsdb_status(fetch_t);

/* variables. */

static const char env_api_key[] = "DNSDB_API_KEY";
static const char env_dnsdb_base_url[] = "DNSDB_SERVER";

static char *api_key = NULL;
static char *dnsdb_base_url = NULL;

static const char dnsdb2_url_prefix[] = "/dnsdb/v2";


/*---------------------------------------------------------------- public
 */

#if WANT_PDNS_DNSDB2
/* a list of API key prefixes that may not use the Flex API */
static const char *blocked_api_key_prefixes[] = {
	"dce-",
	NULL
};

static const struct pdns_system dnsdb2 = {
	"dnsdb2", "https://api.dnsdb.info/dnsdb/v2",
	dnsdb_url, dnsdb_auth, dnsdb_status, dnsdb_setval,
	dnsdb_ready, dnsdb_destroy
};

pdns_system_ct
pdns_dnsdb2(void) {
	return &dnsdb2;
}
#endif /* WANT_PDNS_DNSDB2 */

/*---------------------------------------------------------------- private
 */

static bool
api_key_blocked(const char *test_api_key)
{
	const char **block_list = blocked_api_key_prefixes;
	while (*block_list != NULL) {
		if (strncmp(*block_list, test_api_key, strlen(*block_list)) == 0)
			return true;
		block_list++;
	}
	return false;
}

/* dnsdb_setval() -- install configuration element
 */
static const char *
dnsdb_setval(const char *key, const char *value) {
	if (strcmp(key, "apikey") == 0) {
		DESTROY(api_key);
		api_key = strdup(value);
	} else if (strcmp(key, "server") == 0) {
		DESTROY(dnsdb_base_url);
		dnsdb_base_url = strdup(value);
	} else {
		return "dnsdb_setval() unrecognized key";
	}
	return NULL;
}

/* dnsdb_ready() -- override the config file from environment variables?
 */
static const char *
dnsdb_ready(void) {
	const char *value;

	if ((value = getenv(env_api_key)) != NULL) {
		dnsdb_setval("apikey", value);
		DEBUG(1, true, "conf env api_key was set\n");
	}
	if ((value = getenv(env_dnsdb_base_url)) != NULL) {
		dnsdb_setval("server", value);
		DEBUG(1, true, "conf env dnsdb_server = '%s'\n",
		      dnsdb_base_url);
	}
	if (dnsdb_base_url == NULL)
		dnsdb_base_url = strdup(psys->base_url);

	/* If SAF (aka APIv2) ensure URL contains special /dnsdb/v2 prefix. */
	if (strstr(dnsdb_base_url, dnsdb2_url_prefix) == NULL) {
		int x;
		char *ret;
		x = asprintf(&ret, "%s%s", dnsdb_base_url, dnsdb2_url_prefix);
		if (x < 0) {
			perror("asprintf");
			abort();
		}
		DESTROY(dnsdb_base_url);
		dnsdb_base_url = ret;
	}

	if (api_key_blocked(api_key)) {
		return "The type of API key given is not allowed to use"
			" the DNSDB Flex API";
	}

	if (api_key == NULL)
		return "no API key given";
	return NULL;
}

/* dnsdb_destroy() -- drop heap storage
 */
static void
dnsdb_destroy(void) {
	DESTROY(api_key);
	DESTROY(dnsdb_base_url);
}

/* dnsdb_url -- create a URL corresponding to a command-path string.
 *
 * the batch file and command line syntax are in native DNSDB API format.
 * this function has the opportunity to crack this into pieces, and re-form
 * those pieces into the URL format needed by some other DNSDB-like system
 * which might have the same JSON output format but a different REST syntax.
 * returns a string that must be freed.
 */
static char *
dnsdb_url(const char *path, char *sep, qdesc_ct qdp, pdns_fence_ct fp) {
	const char *p, *scheme_if_needed;
	char *ret = NULL, *offset_str = NULL,
		*first_after_str = NULL, *first_before_str = NULL,
		*last_after_str = NULL, *last_before_str = NULL,
		*query_limit_str = NULL, *exclude_str = NULL;
	int x;

	/* count the number of slashes in the url, 2 is the base line,
	 * from "//".  3 or more means there's a /path after the host.
	 * In that case, don't add /[verb] here, and also don't allow
	 * selecting a verb that's not "lookup" since the /path could
	 * include its own verb. (this is from an old python-era rule.)
	 */
	x = 0;
	for (p = dnsdb_base_url; *p != '\0'; p++)
		x += (*p == '/');

	/* supply a scheme if the server string did not. */
	scheme_if_needed = "";
	if (strstr(dnsdb_base_url, "://") == NULL)
		scheme_if_needed = "https://";

	if (qdp->offset > 0) {
		x = asprintf(&offset_str, "&offset=%ld", qdp->offset);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (qdp->query_limit != -1) {
		x = asprintf(&query_limit_str, "&limit=%ld", qdp->query_limit);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (fp->first_after != 0) {
		x = asprintf(&first_after_str, "&time_first_after=%lu",
			     fp->first_after);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->first_before != 0) {
		x = asprintf(&first_before_str, "&time_first_before=%lu",
			     fp->first_before);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->last_after != 0) {
		x = asprintf(&last_after_str, "&time_last_after=%lu",
			     fp->last_after);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}
	if (fp->last_before != 0) {
		x = asprintf(&last_before_str, "&time_last_before=%lu",
			     fp->last_before);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	if (qdp->exclude != NULL) {
		x = asprintf(&exclude_str, "&exclude=%s",
			     qdp->exclude);
		if (x < 0) {
			perror("asprintf");
			goto done;
		}
	}

	x = asprintf(&ret, "%s%s/%s?swclient=%s&version=%s%s%s%s%s%s%s%s",
		     scheme_if_needed, dnsdb_base_url, path,
		     id_swclient, id_version, 
		     or_else(offset_str, ""),
		     or_else(query_limit_str, ""),
		     or_else(first_after_str, ""),
		     or_else(first_before_str, ""),
		     or_else(last_after_str, ""),
		     or_else(last_before_str, ""),
		     or_else(exclude_str, ""));
	if (x < 0) {
		perror("asprintf");
		goto done;
	}

	/* because we append query parameters, tell the caller to use & for
	 * any further query parameters.
	 */
	if (sep != NULL)
		*sep = '&';

 done:
	DESTROY(offset_str);
	DESTROY(query_limit_str);
	DESTROY(first_after_str);
	DESTROY(first_before_str);
	DESTROY(last_after_str);
	DESTROY(last_before_str);
	return (ret);
}

static void
dnsdb_auth(fetch_t fetch) {
	if (api_key != NULL) {
		char *key_header;

		if (asprintf(&key_header, "X-Api-Key: %s", api_key) < 0)
			my_panic(true, "asprintf");
		fetch->hdrs = curl_slist_append(fetch->hdrs, key_header);
		DESTROY(key_header);
	}
}

static const char *
dnsdb_status(fetch_t fetch __attribute__ ((unused))) {
	return status_error;
}

#endif /*WANT_PDNS_DNSDB || WANT_PDNS_DNSDB2*/
