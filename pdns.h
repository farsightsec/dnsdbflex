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

#ifndef PDNS_H_INCLUDED
#define PDNS_H_INCLUDED 1

#include <jansson.h>
#include "netio.h"

/* main is the primary jansson library object from a json_loadb().
 * all the other fields in this structure will point inside main, as
 * borrowed references, so const.  main must be deallocated
 * by json_decref() which then invalidates all the other fields.
 *
 * cof_obj points to the object that contains time_first...num_results.
 * saf_cond, saf_msg, and saf_obj are
 * parsed from main and cof_obj is repointed to saf_obj.
 */
struct pdns_json {
	json_t *main;
	const json_t *saf_obj, *saf_cond, *saf_msg,
		*rrname, *rrtype, *count, *time_first, *time_last,
		*rdata, *raw_rdata;
};

struct pdns_tuple {
	struct pdns_json  obj;
	const char	 *cond, *msg;
	const char	 *rrname, *rrtype;
	json_int_t	  count;
	u_long		  time_first, time_last;
	const char	 *rdata, *raw_rdata;
};
typedef struct pdns_tuple *pdns_tuple_t;
typedef const struct pdns_tuple *pdns_tuple_ct;

struct pdns_fence {
	u_long	first_after, first_before, last_after, last_before;
};
typedef struct pdns_fence pdns_fence_t;
typedef const struct pdns_fence *pdns_fence_ct;

struct pdns_system {
	/* name of this pdns system, as specifiable by the user. */
	const char	*name;

	/* default URL to reach this pdns API endpoint.	 May be overridden. */
	const char	*base_url;

	/* start creating a URL corresponding to a command-path string.
	 * first argument is the input URL path.
	 * second is an output parameter pointing to the separator character
	 * (? or &) that the caller should use between any further URL
	 * parameters.	May be NULL if the caller doesn't care.
	 * the third argument is search parameters.
	 */
	char *		(*url)(const char *, char *, qdesc_ct, pdns_fence_ct);

	/* add authentication information to the fetch request being created.
	 * may be NULL if auth is not needed by this pDNS system.
	 */
	void		(*auth)(fetch_t);

	/* map a non-200 HTTP rcode from a fetch to an error indicator. */
	const char *	(*status)(fetch_t);

	/* set a configuration key-value pair.	Returns NULL if ok;
	 * otherwise returns a static error message.
	 */
	const char *	(*setval)(const char *, const char *);

	/* check if ready with enough config settings to try API queries.
	 * Returns NULL if ready; otherwise returns a static error message.
	 */
	const char *	(*ready)(void);

	/* drop heap storage. */
	void		(*destroy)(void);
};
typedef const struct pdns_system *pdns_system_ct;

typedef void (*present_t)(pdns_tuple_ct, const char *, size_t, writer_t);

/*
 * Possible variations of output:
 *
 * default: json
 *
 * -F: batch file output, same name may be repeated with different rrtypes.
 *
 * -T: batch file output, same name will not be repeated with different rrtypes
 *
 */
typedef enum { pres_json, pres_batch, pres_batch_dedup_rrtype } present_e;

void present_json(pdns_tuple_ct, const char *, size_t, writer_t);
void present_batch(pdns_tuple_ct, const char *, size_t, writer_t);
void present_batch_dedup_rrtype(pdns_tuple_ct, const char *, size_t, writer_t);
const char *tuple_make(pdns_tuple_t, const char *, size_t);
void tuple_unmake(pdns_tuple_t);
int data_blob(query_t, const char *, size_t);

/* Any HTTP status codes we handle specifically */
#define HTTP_OK		   200

#endif /*PDNS_H_INCLUDED*/
