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

#ifndef NETIO_H_INCLUDED
#define NETIO_H_INCLUDED 1

#include <stdbool.h>
#include <curl/curl.h>

typedef enum { method_none = 0, method_regex, method_glob } search_method_t;

typedef enum { search_none = 0, search_rrnames, search_rdata } what_to_search_t;

typedef enum { return_none = 0, return_terse, return_details } what_to_return_t;

/* query parameters descriptor. */
struct qdesc {
	search_method_t	  search_method;
	what_to_search_t  what_to_search;
	what_to_return_t  what_to_return;
	char		 *value;
	char		 *exclude;
	char		 *rrtype;
	u_long		  after;
	u_long		  before;
	bool		  complete;
	long		  query_limit;
	long		  output_limit;
	long		  offset;
};
typedef struct qdesc *qdesc_t;
typedef const struct qdesc *qdesc_ct;

/* official SAF condition values, plus sc_init, sc_we_limited, and sc_missing.
 */
typedef enum {
	sc_init = 0,	 /* initial condition */
	/* official */
	sc_begin, sc_ongoing, sc_succeeded, sc_limited, sc_failed,
	sc_we_limited,	 /* we noticed we hit the output limit */
	sc_missing	 /* cond was missing at end of input stream */
} saf_cond_e;

/* API fetch. */
struct fetch {
	struct query	*query;
	CURL		*easy;
	struct curl_slist  *hdrs;
	char		*url;
	char		*buf;
	size_t		len;
	long		rcode;
	bool		stopped;
};
typedef struct fetch *fetch_t;

/* one query. */
struct query {
	struct fetch	*fetch;
	struct writer	*writer;
	struct qdesc	qd;
	char		*command;
	/* invariant: (status == NULL) == (writer == NULL) */
	char		*status;
	char		*message;
	bool		hdr_sent;
	saf_cond_e	saf_cond;
	char		*saf_msg;
};
typedef struct query *query_t;

/* one output stream. */
struct writer {
	struct query	*query;
	long		output_limit;
	int		count;
};
typedef struct writer *writer_t;

void make_curl(void);
void unmake_curl(void);
void create_fetch(query_t, char *);
writer_t writer_init(long);
void query_status(query_t, const char *, const char *);
size_t writer_func(char *ptr, size_t size, size_t nmemb, void *blob);
void writer_fini(writer_t);
void unmake_writers(void);
void io_engine(int);
void escape(CURL *, char **);

#endif /*NETIO_H_INCLUDED*/
