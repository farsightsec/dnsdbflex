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

/* External. */

/* asprintf() does not appear on linux without this */
#define _GNU_SOURCE

/* gettimeofday() does not appear on linux without this. */
#define _BSD_SOURCE

/* modern glibc will complain about the above if it doesn't see this. */
#define _DEFAULT_SOURCE

#include <sys/wait.h>
#include <sys/time.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>
#include <getopt.h>

/* Types. */

#define MAIN_PROGRAM
#include "defs.h"
#include "pdns.h"
#include "netio.h"
#if WANT_PDNS_DNSDB2
#include "pdns_dnsdb.h"
#endif
#include "time.h"
#include "globals.h"
#undef MAIN_PROGRAM

/* Forward. */

static void help(void);
static pdns_system_ct pick_system(const char *);
static void qdesc_debug(const char *, qdesc_ct);
static __attribute__((noreturn)) void usage(const char *, ...);
static bool parse_long(const char *, long *);
static void read_configs(void);
static char *makepath(qdesc_ct);
static void query_launcher(qdesc_ct, writer_t);
static const char *check_printable_ascii(const char *);
static void check_glob_trailing_char(bool, qdesc_ct);

/* Constants. */

static const char * const conf_files[] = {
	"~/.isc-dnsdb-query.conf",
	"~/.dnsdb-query.conf",
	"/etc/isc-dnsdb-query.conf",
	"/etc/dnsdb-query.conf",
	NULL
};

/* Private. */

static bool force_query = false;

/* Public. */

int
main(int argc, char *argv[]) {
	static struct qdesc qd = {
		method_none, search_rrnames, return_details,
		.value = NULL, .exclude = NULL, .rrtype = NULL,
		.after = 0, .before = 0, .complete = false,
		.query_limit = -1, .output_limit = -1, .offset = 0 };
	const char *msg;
	int ch;
	size_t sz;

	/* global dynamic initialization. */
	gettimeofday(&startup_time, NULL);
	if ((program_name = strrchr(argv[0], '/')) == NULL)
		program_name = argv[0];
	else
		program_name++;

	int option_index = 0;

	/* All the getopt_long switches use the following enum */
	static enum {
		long_opt_none,		/* nothing specified */
		long_opt_exclude,	/* --exclude */
		long_opt_force,		/* --force */
		long_opt_glob,		/* --glob */
		long_opt_mode,		/* --mode */
		long_opt_regex		/* --regex */
	} long_opt_switch = long_opt_none;

	static struct option long_options[] = {
		/* NAME	    ARGUMENT	       FLAG  SHORTNAME */
		{"exclude", required_argument, (int*)&long_opt_switch,
		 long_opt_exclude},
		{"force",   no_argument,       (int*)&long_opt_switch,
		 long_opt_force},
		{"glob",    required_argument, (int*)&long_opt_switch,
		 long_opt_glob},
		{"mode",    required_argument, (int*)&long_opt_switch,
		 long_opt_mode},
		{"regex",   required_argument, (int*)&long_opt_switch,
		 long_opt_regex},
		{NULL,	    0,			NULL, 0}
	};

	/* process the command line options. */
	while ((ch = getopt_long(argc, argv,
				 "jr:n:u:p:t:b:k:O:s:FT"
				 "dhqUvA:B:L:l:c46",
				 long_options, &option_index))
	       != -1)
	{
		switch (ch) {
		case 0:
			/* long options appear as ch == 0. then we check
			 * the common variable all the long options set.
			 */
			switch (long_opt_switch) {
			case long_opt_regex:
				sz = strlen(optarg);
				if (sz == 0)
					usage("The --regex option requires"
					      " a non-empty argument");
				if (sz > MAX_VALUE_LEN)
					usage("The --regex option is too long"
					      " (%u is the maximum length)",
					      MAX_VALUE_LEN);
				if (qd.value != NULL)
					usage("Cannot specify --glob or"
					      " --regex more than once");
				qd.value = strdup(optarg);
				qd.search_method = method_regex;
				break;
			case long_opt_glob:
				sz = strlen(optarg);
				if (sz == 0)
					usage("The --glob option requires a"
					      " non-empty argument");
				if (sz > MAX_VALUE_LEN)
					usage("The --glob option is too long"
					      " (%u is the maximum length)",
					      MAX_VALUE_LEN);
				if (qd.value != NULL)
					usage("Cannot specify --glob or"
					      " --regex more than once");
				qd.value = strdup(optarg);
				qd.search_method = method_glob;
				break;
			case long_opt_exclude:
				sz = strlen(optarg);
				if (sz == 0)
					usage("The --exclude option requires"
					      " a non-empty argument");
				if (sz > MAX_VALUE_LEN)
					usage("The --exclude option is too"
					      " long (%u is the maximum"
					      " length)",
					      MAX_VALUE_LEN);
				if (qd.exclude != NULL)
					usage("Cannot specify --exclude"
					      " more than once");
				qd.exclude = strdup(optarg);
				break;
			case long_opt_force:
				force_query = true;
				break;
			case long_opt_mode:
				sz = strlen(optarg);
				if (sz == 0)
					usage("The --mode option requires"
					      " a non-empty argument");
                                /* allow abbreviations t for terse and d for details */
                                if (strcmp(optarg, "terse") == 0 ||
                                    strcmp(optarg, "t") == 0)
                                        qd.mode_to_return = return_terse;
#ifdef DETAILS_SUPPORTED
                                else if (strcmp(optarg, "details") == 0 ||
                                         strcmp(optarg, "d") == 0)
                                        qd.mode_to_return = return_details;
#endif
                                else
#ifdef DETAILS_SUPPORTED
                                        usage("Illegal mode value, "
                                              "must be 'terse'|'t' or 'details'|'d'");
#else
				        usage("Illegal mode value, "
                                              "must be 'terse'|'t'");
#endif
                                break;
			case long_opt_none: /* FALLTHROUGH */
			default:
				/* NOTREACHED */
				/* handled in outer default case */
				break;
			}
			break;
		case 'A':
			if (!time_get(optarg, &qd.after) || qd.after == 0UL)
				usage("bad -A timestamp");
			break;
		case 'B':
			if (!time_get(optarg, &qd.before) || qd.before == 0UL)
				usage("bad -B timestamp");
			break;
		case 'c':
			qd.complete = true;
			break;
		case 'd':
			debug_level++;
			break;
		case 'F':
			presentation = pres_batch;
			break;
		case 'h':
			help();
			my_exit(0);
		case 'j':
			presentation = pres_json;
			break;
		case 'l':
			if (!parse_long(optarg, &qd.query_limit) ||
			    (qd.query_limit < 0))
				usage("-l must be zero or positive");
			break;
		case 'L':
			if (!parse_long(optarg, &qd.output_limit) ||
			    (qd.output_limit <= 0))
				usage("-L must be positive");
			break;
		case 'O':
			if (!parse_long(optarg, &qd.offset) || (qd.offset < 0))
				usage("-O must be zero or positive");
			break;
		case 'q':
			quiet = true;
			break;
		case 's':
			/* allow abbreviations n for rrnames and d for rdata */
			if (strcmp(optarg, "rrnames") == 0 ||
			    strcmp(optarg, "n") == 0)
				qd.what_to_search = search_rrnames;
			else if (strcmp(optarg, "rdata") == 0 ||
			    strcmp(optarg, "d") == 0)
				qd.what_to_search = search_rdata;
			else
				usage("Illegal what to search, "
				      "must be 'rrnames'|'n' or 'rdata'|'d'");
			break;
		case 't':
			qd.rrtype = strdup(optarg);
			break;
		case 'T':
			presentation = pres_batch_dedup_rrtype;
			break;
		case 'u':
			if ((psys = pick_system(optarg)) == NULL)
				usage("-u must refer to a pdns system");
			break;
		case 'U':
			donotverify = true;
			break;
		case 'v':
			printf("%s: version %s\n", program_name, id_version);
			my_exit(0);
		case '4':
			curl_ipresolve = CURL_IPRESOLVE_V4;
			break;
		case '6':
			curl_ipresolve = CURL_IPRESOLVE_V6;
			break;
		default:
			usage("unrecognized option");
		}
	}

	argc -= optind;
	if (argc != 0)
		usage("there are no non-option arguments to this program");
	argv = NULL;

	if (qd.value == NULL)
		usage("Need to provide a --regex or --glob option and"
		      " its argument");

	if (qd.search_method == method_glob)
		check_glob_trailing_char(force_query, &qd);
	else if (force_query)
		usage("--force only makes sense with a glob query");

	if (!force_query) {
		msg = check_printable_ascii(qd.value);
		if (msg != NULL)
			usage(msg);

		if (qd.exclude) {
			msg = check_printable_ascii(qd.exclude);
			if (msg != NULL)
				usage(msg);
		}
	}

	/* recondition for HTML use. */
	CURL *easy = curl_easy_init();
	escape(easy, &qd.value);
	escape(easy, &qd.rrtype);
	curl_easy_cleanup(easy);
	easy = NULL;

	if (qd.output_limit == -1 && qd.query_limit != -1)
		qd.output_limit = qd.query_limit;

	if (qd.after != 0 && qd.before != 0) {
		if (qd.after > qd.before)
			usage("-A value must be before -B value (for now)");
	}
	if (qd.complete && qd.after == 0 && qd.before == 0)
		usage("-c without -A or -B makes no sense.");

	/* optionally dump program options as interpreted. */
	if (debug_level >= 1) {
		qdesc_debug("main", &qd);
	}

	/* select presenter. */
	switch (presentation) {
	case pres_json:
		presenter = present_json;
		break;
	case pres_batch:
		presenter = present_batch;
		break;
	case pres_batch_dedup_rrtype:
		presenter = present_batch_dedup_rrtype;
		break;
	default:
		abort();
	}

	/* get to final readiness; in particular, get psys set. */
	read_configs();
	if (psys == NULL) {
		psys = pick_system(DEFAULT_SYS);
		if (psys == NULL)
			usage("neither " DNSDBQ_SYSTEM
			      " nor -u were specified,"
			      " and there is no default.");
	}

	/* verify that some of the fields in our psys are set. */
	assert(psys->base_url != NULL);
	assert(psys->url != NULL);
	assert(psys->status != NULL);
	assert(psys->ready != NULL);
	assert(psys->destroy != NULL);

	if ((msg = psys->ready()) != NULL)
		usage(msg);
	make_curl();
	writer_t writer = writer_init(qd.output_limit);
	query_launcher(&qd, writer);
	io_engine(0);
	writer_fini(writer);
	writer = NULL;
	unmake_curl();

	/* clean up and go home. */
	DESTROY(qd.value);
	DESTROY(qd.rrtype);
	my_exit(exit_code);
}

/* debug -- at the moment, dump to stderr.
 */
void
debug(bool want_header, const char *fmtstr, ...) {
	va_list ap;

	va_start(ap, fmtstr);
	if (want_header)
		fputs("debug: ", stderr);
	vfprintf(stderr, fmtstr, ap);
	va_end(ap);
}

/* my_exit -- close or destroy global objects, then exit.
 */
__attribute__((noreturn)) void
my_exit(int code) {
	/* writers and readers which are still known, must be freed. */
	unmake_writers();

	/* if curl is operating, it must be shut down. */
	unmake_curl();

	/* globals which may have been initialized, are to be freed. */
	if (psys != NULL)
		psys->destroy();

	/* terminate process. */
	DEBUG(1, true, "about to call exit(%d)\n", code);
	exit(code);
}

/* my_panic -- display an error on diagnostic output stream, exit ungracefully
 */
__attribute__((noreturn)) void
my_panic(bool want_perror, const char *s) {
	fprintf(stderr, "%s: ", program_name);
	if (want_perror)
		perror(s);
	else
		fprintf(stderr, "%s\n", s);
	my_exit(1);
}

/* or_else -- return one pointer or else the other.
 */
const char *
or_else(const char *p, const char *or_else) {
	if (p != NULL)
		return p;
	return or_else;
}

/* Private. */

/* help -- display a brief usage-help text; then exit.
 *
 * this goes to stdout since we can expect it not to be piped unless to $PAGER.
 */
static void
help(void) {
	printf("usage: %s [-cdFhjqsTUv46] \n",
	       program_name);
	puts("\t[-l QUERY-LIMIT] [-L OUTPUT-LIMIT] [-A after] [-B before]\n"
	     "\t[-u system] [-O offset]\n"
	     "\t{\n"
	     "\t\t[--regex regex] |\n"
	     "\t\t[--glob glob]\n"
	     "\t}\n"
	     "\t[--exclude glob|regex]\n"
#ifdef DETAILS_SUPPORTED
	     "\t[--mode terse|t|details|d]\n"
#else
	     "\t[--mode terse|t]\n"
#endif
	     "\t[-s rrnames|n|rdata|d]\n"
	     "\t[-t rrtype]\n"
	     "for -A and -B, use absolute format YYYY-MM-DD[ HH:MM:SS],\n"
	     "\tor relative format %dw%dd%dh%dm%ds.\n"
	     "use -c to get complete (strict) time matching for -A and -B.\n"
	     "use -d one or more times to ramp up the diagnostic output.\n"
	     "use -F to get batch mode output.\n"
	     "use -T to get batch mode output with deduplicated rrtypes.\n"
	     "use --force to issue possibly invalid or non-useful queries.\n"
	     "use -O # to skip this many results in what is returned.\n"
	     "use -q for warning reticence.\n"
	     "use -U to turn off SSL certificate verification.\n"
	     "use -4 to force connecting to the server via IPv4.\n"
	     "use -6 to force connecting to the server via IPv6.\n"
	     "use -v to show the program version.\n");

	puts("for -u, system must be one of:");
#if WANT_PDNS_DNSDB2
	puts("\tdnsdb2");
#endif
	puts("\nGetting Started:\n"
	     "\tAdd your API key to ~/.dnsdb-query.conf like this:\n"
	     "\t\tAPIKEY=\"YOURAPIKEYHERE\"");
	printf("\nTry $ man %s for full documentation.\n", program_name);
}

/* pick_system -- return a named system descriptor, or NULL.
 */
static pdns_system_ct
pick_system(const char *name) {
#if WANT_PDNS_DNSDB2
	if (strcmp(name, "dnsdb2") == 0) {
		return pdns_dnsdb2();
	}
#endif
	return NULL;
}

/* qdesc_debug -- dump a qdesc.
 */
static void
qdesc_debug(const char *where, qdesc_ct qdp) {
	debug(true, "qdesc(%s)[", where);

	const char *sep = "\040";
	if (qdp->value != NULL) {
		debug(true, "%sth '%s'", sep, qdp->value);
		sep = ",\040";
	}
	if (qdp->rrtype != NULL) {
		debug(true, "%srr '%s'\n", sep, qdp->rrtype);
		sep = ",\040";
	}
	if (qdp->after != 0) {
		debug(false, "%s-A%ld(%s)",
		      sep, qdp->after, time_str(qdp->after));
		sep = "\n\t";
	}
	if (qdp->before != 0) {
		debug(false, "%s-B%ld(%s)",
		      sep, qdp->before, time_str(qdp->before));
		sep = "\n\t";
	}
	if (qdp->query_limit != -1) {
		debug(false, "%s-l%ld", sep, qdp->query_limit);
		sep = "\040";
	}
	if (qdp->output_limit != -1) {
		debug(false, "%s-L%ld", sep, qdp->output_limit);
		sep = "\040";
	}
	if (qdp->complete) {
		debug(false, "%s-c", sep);
		sep = "\040";
	}
	if (qdp->exclude) {
		debug(false, "%s--exclude=%s", sep, qdp->exclude);
		sep = "\040";
	}
	debug(false, "\040]\n");
}


/* usage -- display a usage error message, brief usage help text; then exit.
 *
 * this goes to stderr in case stdout has been piped or redirected.
 */
static __attribute__((noreturn)) void
usage(const char *fmtstr, ...) {
	va_list ap;

	va_start(ap, fmtstr);
	fputs("error: ", stderr);
	vfprintf(stderr, fmtstr, ap);
	va_end(ap);
	fputs("\n\n", stderr);
	fprintf(stderr,
		"try   %s -h   for a short description of program usage.\n",
		program_name);
	my_exit(1);
}

/* parse a base 10 long value.
 *
 * Return true if ok, else return false.
 */
static bool
parse_long(const char *in, long *out) {
	char *ep;
	long result;

	/* "The strtol() function shall not change the setting of errno
	 * if successful." (IEEE Std 1003.1, 2004 Edition)
	 */
	errno = 0;
	result = strtol(in, &ep, 10);
	if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) ||
	    (errno != 0 && result == 0) ||
	    (ep == in))
		return false;
	*out = result;
	return true;
}

/* read_configs -- try to find a config file in static path, then parse it.
 */
static void
read_configs(void) {
	const char * const *conf;
	char *cf = NULL;

	for (conf = conf_files; *conf != NULL; conf++) {
		wordexp_t we;

		wordexp(*conf, &we, WRDE_NOCMD);
		cf = strdup(we.we_wordv[0]);
		assert(cf != NULL);
		wordfree(&we);
		if (access(cf, R_OK) == 0) {
			DEBUG(1, true, "conf found: '%s'\n", cf);
			break;
		}
		DESTROY(cf);
	}
	if (cf != NULL) {
		char *cmd, *line;
		size_t n;
		int x, l;
		FILE *f;

		/* in the "echo dnsdb server..." lines, the
		 * first parameter is the pdns system to which to dispatch
		 * the key and value (i.e. second the third parameters).
		 */
		x = asprintf(&cmd,
			     ". %s;"
			     "echo dnsdbq system $" DNSDBQ_SYSTEM ";"
#if WANT_PDNS_DNSDB2
			     "echo dnsdb2 apikey $APIKEY;"
			     "echo dnsdb2 server $DNSDB_SERVER;"
#endif
			     "exit", cf);
		DESTROY(cf);
		if (x < 0)
			my_panic(true, "asprintf");
		f = popen(cmd, "r");
		if (f == NULL) {
			fprintf(stderr, "%s: [%s]: %s",
				program_name, cmd, strerror(errno));
			DESTROY(cmd);
			my_exit(1);
		}
		DEBUG(1, true, "conf cmd = '%s'\n", cmd);
		DESTROY(cmd);
		line = NULL;
		n = 0;
		l = 0;
		while (getline(&line, &n, f) > 0) {
			char *tok1, *tok2, *tok3;
			char *saveptr = NULL;
			const char *msg;

			l++;
			if (strchr(line, '\n') == NULL) {
				fprintf(stderr,
					"%s: conf line #%d: too long\n",
					program_name, l);
				my_exit(1);
			}
			tok1 = strtok_r(line, "\040\012", &saveptr);
			tok2 = strtok_r(NULL, "\040\012", &saveptr);
			tok3 = strtok_r(NULL, "\040\012", &saveptr);
			if (tok1 == NULL || tok2 == NULL) {
				fprintf(stderr,
					"%s: conf line #%d: malformed\n",
					program_name, l);
				my_exit(1);
			}
			if (tok3 == NULL || *tok3 == '\0') {
				/* variable wasn't set, ignore the line. */
				continue;
			}

			/* some env/conf variables are dnsdbq-specific. */
			if (strcmp(tok1, "dnsdbq") == 0) {
				/* env/config psys does not override -u. */
				if (psys == NULL &&
				    strcmp(tok2, "system") == 0)
				{
					psys = pick_system(tok3);
					if (psys == NULL) {
						fprintf(stderr,
							"%s: unknown %s %s\n",
							program_name,
							DNSDBQ_SYSTEM,
							tok3);
						my_exit(1);
					}
				}
				continue;
			}

			/* this is the last point where psys can be null. */
			if (psys == NULL) {
				/* first match wins and is sticky. */
				if ((psys = pick_system(tok1)) == NULL)
					continue;
				DEBUG(1, true, "picked system %s\n", tok1);
			}

			/* if this variable is for this system, consume it. */
			if (strcmp(tok1, psys->name) == 0) {
				DEBUG(1, true, "line #%d: sets %s|%s|%s\n",
				      l, tok1, tok2,
				      strcmp(tok2, "apikey") == 0
					? "..." : tok3);
				msg = psys->setval(tok2, tok3);
				if (msg != NULL)
					usage(msg);
			}
		}
		DESTROY(line);
		pclose(f);
	}
}

/* makepath -- make a RESTful URI that describes these search parameters.
 *
 * Returns a string that must be free()d.
 */
static char *
makepath(qdesc_ct qdp)
{
	const char *search_method_s;
	const char *what_to_search_s;
	char *command;
	int x;

	if (qdp->search_method == method_regex)
		search_method_s = "regex";
	else if (qdp->search_method == method_glob)
		search_method_s = "glob";
	else
		my_panic(true, "bad search_method");

	if (qdp->what_to_search == search_rrnames)
		what_to_search_s = "rrnames";
	else if (qdp->what_to_search == search_rdata)
		what_to_search_s = "rdata";
	else
		my_panic(true, "bad what_to_search");

#ifdef DETAILS_SUPPORTED
// use qdp->mode_to_return as a URL query parameter
//	if (qdp->mode_to_return == return_terse)
//	else if (qdp->mode_to_return == return_details)
//	else my_panic(true, "bad mode_to_return");
#endif
	/* alternatively, could explicitly default to rrtype=ANY */
	if (qdp->rrtype != NULL)
		x = asprintf(&command, "%s/%s/%s/%s",
			     search_method_s, what_to_search_s,
			     qdp->value,
			     qdp->rrtype);
	else
		x = asprintf(&command, "%s/%s/%s",
			     search_method_s, what_to_search_s,
			     qdp->value);
	if (x < 0)
		my_panic(true, "asprintf");

	return (command);
}

/* query_launcher -- fork off curl job for this query.
 */
void
query_launcher(qdesc_ct qdp, writer_t writer) {
	struct pdns_fence fence = {};
	query_t query = NULL;
	char *url;

	CREATE(query, sizeof(struct query));
	query->writer = writer;
	query->qd = *qdp;
	writer = NULL;
	query->writer->query = query;
	query->command = makepath(qdp);

	/* figure out from time fencing which job(s) we'll be starting.
	 *
	 * the 4-tuple is: first_after, first_before, last_after, last_before
	 */
	if (qdp->after != 0) {
		if (qdp->complete) {
			/* each db tuple must begin after the fence-start. */
			fence.first_after = qdp->after;
		} else {
			/* each db tuple must end after the fence-start. */
			fence.last_after = qdp->after;
		}
	}
	if (qdp->before != 0) {
		if (qdp->complete) {
			/* each db tuple must end before the fence-end. */
			fence.last_before = qdp->before;
		} else {
			/* each db tuple must begin before the fence-end. */
			fence.first_before = qdp->before;
		}
	}

	url = psys->url(query->command, NULL, &query->qd, &fence);
	if (url == NULL)
		my_exit(1);

	DEBUG(1, true, "url [%s]\n", url);

	create_fetch(query, url);
}

/* check if its argument is printable ASCII.
 *
 * returns NULL on success, else an error message.
 */
static const char *
check_printable_ascii(const char *name) {
	int ch;

	while ((ch = *name++) != '\0')
		if (!isprint(ch))
			return "expression argument is not printable ASCII.\n"
				"Use \\DDD to encode non-printable "
				"characters, where DDD is the decimal value "
				"of the character";
	return NULL;
}

/* check if a glob ends in a useful character.
 * If warn_only then just warn; otherwise it is fatal.
 */
static void
check_glob_trailing_char(bool warn_only, qdesc_ct qdp) {
	const char *msg = NULL;

	size_t sz = strlen(qdp->value);
	if (sz == 0)
		usage("search argument is blank."); /* FATAL always */

	int last_ch = qdp->value[sz - 1];

	if (last_ch == '*' || last_ch == '?' || last_ch == ']' ||
	    last_ch == '.')
		return;		/* fine */

	if (qdp->what_to_search == search_rdata) {
		if (last_ch == '"')
			return;		/* fine, but only for rdata */
		msg = "a glob search argument for rdata should end either"
			" in a period,\n"
			"a double quote, or certain "
			"glob special characters (*, ?, or ]).";
	} else
		msg = "a glob search argument for rrnames should end either"
			" in a period\n"
			"or certain glob special characters (*, ?, or ]).";
	if (warn_only) {
		if (!quiet)
			fprintf(stderr, "Warning: %s\nYou may not get results"
				" from your search.\n", msg);
	} else {
		fprintf(stderr, "Error: %s\nYou may not get results from your"
			" search.\n", msg);
		my_exit(1);
	}
}
