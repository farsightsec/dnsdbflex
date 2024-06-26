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

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "netio.h"
#include "pdns.h"
#include "globals.h"

static void io_drain(void);
static void fetch_reap(fetch_t);
static void fetch_done(fetch_t);
static void fetch_unlink(fetch_t);
static void query_done(query_t);

static writer_t writers = NULL;
static CURLM *multi = NULL;
static bool curl_cleanup_needed = false;

const char saf_begin[] = "begin";
const char saf_ongoing[] = "ongoing";
const char saf_succeeded[] = "succeeded";
const char saf_limited[] = "limited";
const char saf_failed[] = "failed";

const char *saf_valid_conds[] = {
	saf_begin, saf_ongoing, saf_succeeded, saf_limited, saf_failed
};

/* make_curl -- perform global initializations of libcurl.
 */
void
make_curl(void) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_cleanup_needed = true;
	multi = curl_multi_init();
	if (multi == NULL) {
		my_logf("curl_multi_init() failed");
		my_exit(1);
	}
}

/* unmake_curl -- clean up and discard libcurl's global state.
 */
void
unmake_curl(void) {
	if (multi != NULL) {
		curl_multi_cleanup(multi);
		multi = NULL;
	}
	if (curl_cleanup_needed) {
		curl_global_cleanup();
		curl_cleanup_needed = false;
	}
}

/* fetch -- given a url, tell libcurl to go fetch it.
 */
void
create_fetch(query_t query, char *url) {
	fetch_t fetch = NULL;
	CURLMcode res;

	DEBUG(2, true, "fetch(%s)\n", url);
	CREATE(fetch, sizeof *fetch);
	fetch->query = query;
	query = NULL;
	fetch->easy = curl_easy_init();
	if (fetch->easy == NULL) {
		/* an error will have been output by libcurl in this case. */
		DESTROY(fetch);
		DESTROY(url);
		my_exit(1);
	}
	fetch->url = url;
	url = NULL;
	curl_easy_setopt(fetch->easy, CURLOPT_URL, fetch->url);
	if (donotverify) {
		curl_easy_setopt(fetch->easy, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(fetch->easy, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	/* if user specified a prefence for IPv4 or IPv6, use it. */
	if (curl_ipresolve != CURL_IPRESOLVE_WHATEVER)
		curl_easy_setopt(fetch->easy,
				 CURLOPT_IPRESOLVE, curl_ipresolve);

	if (curl_timeout != 0L) {
		curl_easy_setopt(fetch->easy,
				 CURLOPT_CONNECTTIMEOUT, curl_timeout);
		curl_easy_setopt(fetch->easy,
				 CURLOPT_TIMEOUT, curl_timeout);
	}

	if (psys->auth != NULL)
	    psys->auth(fetch);

	fetch->hdrs = curl_slist_append(fetch->hdrs, jsonl_header);
	curl_easy_setopt(fetch->easy, CURLOPT_HTTPHEADER, fetch->hdrs);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEFUNCTION, writer_func);
	curl_easy_setopt(fetch->easy, CURLOPT_WRITEDATA, fetch);
	curl_easy_setopt(fetch->easy, CURLOPT_PRIVATE, fetch);
#ifdef CURL_AT_LEAST_VERSION
/* If CURL_AT_LEAST_VERSION is not defined then the curl is probably too old */
#if CURL_AT_LEAST_VERSION(7,42,0)
	/* do not allow curl to swallow /./ and /../ in our URLs */
	curl_easy_setopt(fetch->easy, CURLOPT_PATH_AS_IS, 1L);
#endif
#endif /* CURL_AT_LEAST_VERSION */
	if (debug_level >= 3)
		curl_easy_setopt(fetch->easy, CURLOPT_VERBOSE, 1L);

	fetch->query->fetch = fetch;

	res = curl_multi_add_handle(multi, fetch->easy);
	if (res != CURLM_OK) {
		my_logf("curl_multi_add_handle() failed: %s",
			curl_multi_strerror(res));
		my_exit(1);
	}
}

/* fetch_reap -- reap one fetch.
 */
static void
fetch_reap(fetch_t fetch) {
	if (fetch->easy != NULL) {
		curl_multi_remove_handle(multi, fetch->easy);
		curl_easy_cleanup(fetch->easy);
		fetch->easy = NULL;
	}
	if (fetch->hdrs != NULL) {
		curl_slist_free_all(fetch->hdrs);
		fetch->hdrs = NULL;
	}
	DESTROY(fetch->url);
	DESTROY(fetch->buf);
	DESTROY(fetch);
}

/* fetch_done -- deal with consequences of end-of-fetch.
 */
static void
fetch_done(fetch_t fetch) {
	query_t query = fetch->query;

	query_done(query);
}

/* fetch_unlink -- disconnect a fetch from its writer.
 */
static void
fetch_unlink(fetch_t fetch) {
	assert(fetch == fetch->query->fetch);
	fetch->query->fetch = NULL;
	fetch->query = NULL;
}

/* writer_init -- instantiate a writer
 */
writer_t
writer_init(long output_limit) {
	writer_t writer = NULL;

	CREATE(writer, sizeof(struct writer));
	writer->output_limit = output_limit;

	return (writer);
}

/* query_status -- install a status code and description in a query.
 */
void
query_status(query_t query, const char *status, const char *message) {
	assert((query->status == NULL) == (query->message == NULL));
	assert(query->status == NULL);
	query->status = strdup(status);
	query->message = strdup(message);
}

/* writer_func -- process a block of json text.
 *
 * This function's signature must conform to write_callback() in
 * CURLOPT_WRITEFUNCTION.
 * Returns the number of bytes actually taken care of or returns
 * CURL_WRITEFUNC_PAUSE to pause this query's connection until
 * curl_easy_pause(..., CURLPAUSE_CONT) is called.
 */
size_t
writer_func(char *ptr, size_t size, size_t nmemb, void *blob) {
	fetch_t fetch = (fetch_t) blob;
	query_t query = fetch->query;
	writer_t writer = query->writer;
	size_t bytes = size * nmemb;
	char *nl;

	DEBUG(3, true, "writer_func(%d, %d): %d\n",
	      (int)size, (int)nmemb, (int)bytes);

	fetch->buf = realloc(fetch->buf, fetch->len + bytes);
	memcpy(fetch->buf + fetch->len, ptr, bytes);
	fetch->len += bytes;

	/* when the fetch is a live web result, emit
	 * !2xx errors and info payloads as reports.
	 */
	if (fetch->easy != NULL) {
		if (fetch->rcode == 0)
			curl_easy_getinfo(fetch->easy,
					  CURLINFO_RESPONSE_CODE,
					  &fetch->rcode);
		if (fetch->rcode != HTTP_OK) {
			char *message = strndup(fetch->buf, fetch->len);

			/* only report the first line of data. */
			char *eol = strpbrk(message, "\r\n");
			if (eol != NULL)
				*eol = '\0';

			/* if the message (that's left) is just <html>,
			 * change it to an HTTP Status code */
			if (strcasecmp(message, "<html>") == 0) {
				DESTROY(message);
				if (asprintf(&message, "HTTP Status %ld",
					     fetch->rcode) < 0)
					my_panic(true, "asprintf");
			}

			/* only report the first response status (vs. -m). */
			if (query->status == NULL) {
				query_status(query,
					     psys->status(fetch),
					     message);
				if (!quiet) {
					char *url;

					curl_easy_getinfo(fetch->easy,
							CURLINFO_EFFECTIVE_URL,
							  &url);
					my_logf(
						"warning: "
						"libcurl %ld [%s]",
						fetch->rcode,
						url);
				}
			}
			if (!quiet)
				my_logf("warning: libcurl: [%s]",
					message);
			DESTROY(message);
			fetch->buf[0] = '\0';
			fetch->len = 0;
			return (bytes);
		}
	}

	/* deblock. */
	while ((nl = memchr(fetch->buf, '\n', fetch->len)) != NULL) {
		size_t pre_len = (size_t)(nl - fetch->buf),
			post_len = (fetch->len - pre_len) - 1;

		if (writer->output_limit > 0 &&
		    writer->count >= writer->output_limit)
		{
			DEBUG(9, true, "hit output limit %ld\n",
			      writer->output_limit);
			/* cause CURLE_WRITE_ERROR for this transfer. */
			bytes = 0;
			query->saf_cond = sc_we_limited;
			/* inform io_engine() that the abort is intentional. */
			fetch->stopped = true;
		} else {
			query->writer->count +=
				data_blob(query, fetch->buf, pre_len);

			switch (query->saf_cond) {
			case sc_init:
			case sc_begin:
			case sc_ongoing:
			case sc_missing:
				break;
			case sc_succeeded:
			case sc_limited:
			case sc_failed:
			case sc_we_limited:
				/* inform io_engine() intentional
				 * abort. */
				fetch->stopped = true;
				break;
			}
		}
		memmove(fetch->buf, nl + 1, post_len);
		fetch->len = post_len;
	}

	return (bytes);
}

/* query_done -- do something with leftover buffer data when a query ends.
 */
static void
query_done(query_t query) {
	DEBUG(2, true, "query_done(%s)\n", query->command);

	if (!quiet) {
		const char *msg = or_else(query->saf_msg, "");

		if (query->saf_cond == sc_limited)
			fprintf(stderr, "Query limited: %s\n", msg);
		else if (query->saf_cond == sc_failed)
			fprintf(stderr, "Query failed: %s\n", msg);
		else if (query->saf_cond == sc_missing)
			fprintf(stderr, "Query response_missing: %s\n", msg);
		else if (query->status != NULL)
			fprintf(stderr, "Query status: %s (%s)\n",
				query->status, query->message);
	}
}

/* writer_fini -- stop a writer's fetch
 */
void
writer_fini(writer_t writer) {
	/* finish and close any fetches still cooking. */
	if (writer->query != NULL) {
		query_t query = writer->query;

		/* release any buffered info. */
		if (query->fetch != NULL) {
			DESTROY(query->fetch->buf);
			if (query->fetch->len != 0) {
				my_logf(
					"warning: stranding %d octets!",
					(int)query->fetch->len);
				query->fetch->len = 0;
			}

			/* tear down any curl infrastructure on the fetch. */
			fetch_reap(query->fetch);

			query->fetch = NULL;
		}
		assert((query->status != NULL) == (query->message != NULL));
		DESTROY(query->status);
		DESTROY(query->message);
		DESTROY(query->command);
		DESTROY(query);
	}

	DESTROY(writer);
}

void
unmake_writers(void) {
	while (writers != NULL)
		writer_fini(writers);
}

/* io_engine -- let libcurl run until there are few enough outstanding jobs.
 */
void
io_engine(int jobs) {
	int still, repeats, numfds;

	DEBUG(2, true, "io_engine(%d)\n", jobs);

	/* let libcurl run while there are too many jobs remaining. */
	still = 0;
	repeats = 0;
	while (curl_multi_perform(multi, &still) == CURLM_OK && still > jobs) {
		DEBUG(3, true, "...waiting (still %d)\n", still);
		numfds = 0;
		if (curl_multi_wait(multi, NULL, 0, 0, &numfds) != CURLM_OK)
			break;
		if (numfds == 0) {
			/* curl_multi_wait() can return 0 fds for no reason. */
			if (++repeats > 1) {
				struct timespec req, rem;

				req = (struct timespec){
					.tv_sec = 0,
					.tv_nsec = 100*1000*1000  // 100ms
				};
				while (nanosleep(&req, &rem) == EINTR) {
					/* as required by nanosleep(3). */
					req = rem;
				}
			}
		} else {
			repeats = 0;
		}
		io_drain();
	}
	io_drain();
}

/* io_drain -- drain the response code reports.
 */
static void
io_drain(void) {
	struct CURLMsg *cm;
	int still = 0;

	while ((cm = curl_multi_info_read(multi, &still)) != NULL) {
		fetch_t fetch;
		query_t query;
		char *private;

		curl_easy_getinfo(cm->easy_handle,
				  CURLINFO_PRIVATE,
				  &private);
		fetch = (fetch_t) private;
		query = fetch->query;

		if (cm->msg == CURLMSG_DONE) {
			if (fetch->rcode == 0)
				curl_easy_getinfo(fetch->easy,
						  CURLINFO_RESPONSE_CODE,
						  &fetch->rcode);

			DEBUG(2, true, "io_drain(%s) DONE rcode=%d\n",
			      query->command, fetch->rcode);
			DEBUG(2, true, "... saf_cond %d saf_msg %s\n",
			      query->saf_cond,
			      or_else(query->saf_msg, ""));

			if (cm->data.result == CURLE_COULDNT_RESOLVE_HOST) {
				my_logf(
					"warning: libcurl failed since "
					"could not resolve host");
				exit_code = 1;
			} else if (cm->data.result == CURLE_COULDNT_CONNECT) {
				my_logf(
					"warning: libcurl failed since "
					"could not connect");
				exit_code = 1;
			} else if (cm->data.result != CURLE_OK &&
				   !fetch->stopped)
			{
				my_logf(
					"warning: libcurl failed with "
					"curl error %d (%s)",
					cm->data.result,
					curl_easy_strerror(cm->data.result));
				exit_code = 1;
			}

			/* record emptiness as status if nothing else. */
			if (query->writer != NULL &&
			    query->writer->count == 0 &&
			    query->status == NULL)
			{
				query_status(query,
					     status_noerror,
					     "no results found for query.");
			}

			fetch_done(fetch);
			fetch_unlink(fetch);
			fetch_reap(fetch);
		}
		DEBUG(3, true, "...info read (still %d)\n", still);
	}
}

/* escape -- HTML-encode a string, in place.
 */
void
escape(CURL *easy, char **str) {
	char *escaped;

	if (*str == NULL)
		return;
	escaped = curl_easy_escape(easy, *str, (int)strlen(*str));
	if (escaped == NULL) {
		my_logf("curl_escape(%s) failed",
			*str);
		my_exit(1);
	}
	DESTROY(*str);
	*str = strdup(escaped);
	curl_free(escaped);
	escaped = NULL;
}
