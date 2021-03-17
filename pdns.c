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

#include <assert.h>
#include <ctype.h>

#include "defs.h"
#include "netio.h"
#include "pdns.h"
#include "time.h"
#include "globals.h"

/*
 * List of rrtypes whose rdata values can be printed out literally.
 * This means they contain just a DNS name in them.
 * This should should contain the upper case rrtype name and its TYPE##
 * equivalent.
 */
const char *printable_rrtypes[] = {
	"CNAME", "TYPE5",
	"NS",	 "TYPE2",
	"PTR",	 "TYPE12",
	"MB",	 "TYPE7",
	"MD",	 "TYPE3",
	"MF",	 "TYPE4",
	"MG",	 "TYPE8",
	"MR",	 "TYPE9"
};

/* check if this rdata for rrtype should be output as literal or raw
 *
 * returns true if yes, else false.
 */
static bool
rrtype_ok_to_print_literal(const char *rrtype) {
	unsigned i;

	if (rrtype == NULL)
		return false;
	/* convert rrtype to an upper-case equivalent in RRTYPE */
	char RRTYPE[12];  /* maximum size of known rrtype names */
	if (strlen(rrtype) >= sizeof RRTYPE) /*  */
		return false;	/* too long to be valid rrtype */
	for (i = 0; i < strlen(rrtype); i++)
		RRTYPE[i] = (char)toupper(rrtype[i]);
	RRTYPE[i] = '\0';

	for (i = 0; i < sizeof(printable_rrtypes) / sizeof (char *); i++)
		if (strcmp(RRTYPE, printable_rrtypes[i]) == 0)
			return true;
	return false;
}

/* present_json -- render one tuple as newline-separated JSON.
 */
void
present_json(pdns_tuple_ct tup,
	     const char *jsonbuf __attribute__ ((unused)),
	     size_t jsonlen __attribute__ ((unused)),
	     writer_t writer __attribute__ ((unused)))
{
	json_dumpf(tup->obj.saf_obj, stdout, JSON_INDENT(0) | JSON_COMPACT);
	putchar('\n');
}

/* present_batch -- render one tuple in a dnsdbq batch input file form,
 * don't deduplicate repeated rrtypes.
 */
void
present_batch(pdns_tuple_ct tup,
	      const char *jsonbuf __attribute__ ((unused)),
	      size_t jsonlen __attribute__ ((unused)),
	      writer_t writer __attribute__ ((unused)))
{
	if (tup->rrname != NULL) {
		printf("rrset/name/%s/%s\n", tup->rrname, tup->rrtype);
	} else if (tup->rdata != NULL) {
		if (rrtype_ok_to_print_literal(tup->rrtype))
		    printf("rdata/name/%s/%s\n",
			   tup->rdata, tup->rrtype);
		else {
			printf("rdata/raw/%s/%s\n",
			       tup->raw_rdata, tup->rrtype);
			printf("# rdata/name/%s/%s\n",
			       tup->rdata, tup->rrtype);
		}
	} else
		my_panic(true, "present_batch");
}

/* present_batch_dedup_rrtype -- render one tuple in a dnsdbq batch input file
 * form, but deduplicate rrtypes
 */
void
present_batch_dedup_rrtype(pdns_tuple_ct tup,
	      const char *jsonbuf __attribute__ ((unused)),
	      size_t jsonlen __attribute__ ((unused)),
	      writer_t writer __attribute__ ((unused)))
{
	/* maintain a one-element "cache" of our previous print out */
#define MAX_BATCH_LINE 8192
	static char last_printed[MAX_BATCH_LINE] = { '\0' };
	char new_printed[MAX_BATCH_LINE];

	if (tup->rrname != NULL) {
		snprintf(new_printed, sizeof new_printed,
			 "rrset/name/%s\n", tup->rrname);
		if (strcmp(new_printed, last_printed) != 0) {
			fputs(new_printed, stdout);
			strcpy(last_printed, new_printed);
		}
		printf("# rrset/name/%s/%s\n", tup->rrname, tup->rrtype);
	} else if (tup->rdata != NULL) {
		if (rrtype_ok_to_print_literal(tup->rrtype))
			snprintf(new_printed, sizeof new_printed,
				 "rdata/name/%s\n", tup->rdata);
		else
			snprintf(new_printed, sizeof new_printed,
				 "rdata/raw/%s\n", tup->raw_rdata);
		if (strcmp(new_printed, last_printed) != 0) {
			fputs(new_printed, stdout);
			strcpy(last_printed, new_printed);
		}
		printf("# rdata/name/%s/%s\n", tup->rdata, tup->rrtype);

	} else
		my_panic(true, "present_batch_dedup_rrtype");
}


/* tuple_make -- create one DNSDB tuple object out of a JSON object.
 */
const char *
tuple_make(pdns_tuple_t tup, const char *buf, size_t len) {
	const char *msg = NULL;
	json_error_t error;

	memset(tup, 0, sizeof *tup);
	DEBUG(4, true, "[%d] '%-*.*s'\n", (int)len, (int)len, (int)len, buf);
	tup->obj.main = json_loadb(buf, len, 0, &error);
	if (tup->obj.main == NULL) {
		fprintf(stderr, "%s: warning: json_loadb: %d:%d: %s %s\n",
			program_name, error.line, error.column,
			error.text, error.source);
		abort();
	}
	if (debug_level >= 4) {
		char *pretty = json_dumps(tup->obj.main, JSON_INDENT(2));
		fprintf(stderr, "debug: %s\n", pretty);
		free(pretty);
	}

	tup->obj.saf_cond = json_object_get(tup->obj.main, "cond");
	if (tup->obj.saf_cond != NULL) {
		if (!json_is_string(tup->obj.saf_cond)) {
			msg = "cond must be a string";
			goto ouch;
		}
		tup->cond = json_string_value(tup->obj.saf_cond);
	}

	tup->obj.saf_msg = json_object_get(tup->obj.main, "msg");
	if (tup->obj.saf_msg != NULL) {
		if (!json_is_string(tup->obj.saf_msg)) {
			msg = "msg must be a string";
			goto ouch;
		}
		tup->msg = json_string_value(tup->obj.saf_msg);
	}

	tup->obj.saf_obj = json_object_get(tup->obj.main, "obj");
	if (tup->obj.saf_obj != NULL) {
		if (!json_is_object(tup->obj.saf_obj)) {
			msg = "obj must be an object";
			goto ouch;
		}
	}

	tup->obj.rrname = json_object_get(tup->obj.saf_obj, "rrname");
	if (tup->obj.rrname != NULL) {
		if (!json_is_string(tup->obj.rrname)) {
			msg = "rrname must be a string";
			goto ouch;
		}
		tup->rrname = json_string_value(tup->obj.rrname);
	}

	tup->obj.rdata = json_object_get(tup->obj.saf_obj, "rdata");
	if (tup->obj.rdata != NULL) {
		if (!json_is_string(tup->obj.rdata)) {
			msg = "rdata must be a string";
			goto ouch;
		}
		tup->rdata = json_string_value(tup->obj.rdata);
	}

	tup->obj.raw_rdata = json_object_get(tup->obj.saf_obj, "raw_rdata");
	if (tup->obj.raw_rdata != NULL) {
		if (!json_is_string(tup->obj.raw_rdata)) {
			msg = "raw_rdata must be a string";
			goto ouch;
		}
		tup->raw_rdata = json_string_value(tup->obj.raw_rdata);
	}

	tup->obj.rrtype = json_object_get(tup->obj.saf_obj, "rrtype");
	if (tup->obj.rrtype != NULL) {
		if (!json_is_string(tup->obj.rrtype)) {
			msg = "rrtype must be a string";
			goto ouch;
		}
		tup->rrtype = json_string_value(tup->obj.rrtype);
	}

	tup->obj.count = json_object_get(tup->obj.saf_obj, "count");
	if (tup->obj.count != NULL) {
		if (!json_is_integer(tup->obj.count)) {
			msg = "count must be an integer";
			goto ouch;
		}
		tup->count = json_integer_value(tup->obj.count);
	}

	tup->obj.time_first = json_object_get(tup->obj.saf_obj, "time_first");
	if (tup->obj.time_first != NULL) {
		if (!json_is_integer(tup->obj.time_first)) {
			msg = "time_first must be an integer";
			goto ouch;
		}
		tup->time_first = (u_long)
			json_integer_value(tup->obj.time_first);
	}

	tup->obj.time_last = json_object_get(tup->obj.saf_obj, "time_last");
	if (tup->obj.time_last != NULL) {
		if (!json_is_integer(tup->obj.time_last)) {
			msg = "time_last must be an integer";
			goto ouch;
		}
		tup->time_last = (u_long)
			json_integer_value(tup->obj.time_last);
	}

	assert(msg == NULL);
	return (NULL);

 ouch:
	assert(msg != NULL);
	tuple_unmake(tup);
	return (msg);
}

/* tuple_unmake -- deallocate the heap storage associated with one tuple.
 */
void
tuple_unmake(pdns_tuple_t tup) {
	json_decref(tup->obj.main);
}

/* data_blob -- process one deblocked json blob as a counted string.
 *
 * presents each blob and then frees it.
 * returns number of tuples processed (for now, 1 or 0).
 */
int
data_blob(query_t query, const char *buf, size_t len) {
	writer_t writer = query->writer;
	const char *msg;
	struct pdns_tuple tup;
	int ret = 0;

	msg = tuple_make(&tup, buf, len);
	if (msg != NULL) {
		fputs(msg, stderr);
		fputc('\n', stderr);
		goto more;
	}

	if (tup.msg != NULL) {
		DEBUG(5, true, "data_blob tup.msg = %s\n", tup.msg);
		query->saf_msg = strdup(tup.msg);
	}

	if (tup.cond != NULL) {
		DEBUG(5, true, "data_blob tup.cond = %s\n", tup.cond);
		/* if we goto next now, this line will not be counted */
		if (strcmp(tup.cond, "begin") == 0) {
			query->saf_cond = sc_begin;
			goto next;
		} else if (strcmp(tup.cond, "ongoing") == 0) {
			/* "cond":"ongoing" key vals should
			 * be ignored but the rest of line used. */
			query->saf_cond = sc_ongoing;
		} else if (strcmp(tup.cond, "succeeded") == 0) {
			query->saf_cond = sc_succeeded;
			goto next;
		} else if (strcmp(tup.cond, "limited") == 0) {
			query->saf_cond = sc_limited;
			goto next;
		} else if (strcmp(tup.cond, "failed") == 0) {
			query->saf_cond = sc_failed;
			goto next;
		} else {
			/* use sc_missing for an invalid cond value  */
			query->saf_cond = sc_missing;
			fprintf(stderr,
				"%s: Unknown value for \"cond\": %s\n",
				program_name, tup.cond);
		}
	}

	/* A COF keepalive will have no "obj" but may have a "cond" or "msg". */
	if (tup.obj.saf_obj == NULL) {
		DEBUG(4, true, "COF object is empty, i.e. a keepalive\n");
		goto next;
	}

	(*presenter)(&tup, buf, len, writer);
	ret = 1;
 next:
	tuple_unmake(&tup);
 more:
	return (ret);
}
