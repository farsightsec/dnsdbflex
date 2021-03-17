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

#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED 1

#ifdef MAIN_PROGRAM
#define EXTERN
#define INIT(...) = __VA_ARGS__
#else
#define EXTERN extern
#define INIT(...)
#endif

EXTERN	const char id_swclient[]	INIT("dnsdbflex");
EXTERN	const char id_version[]		INIT("1.0.5");
EXTERN	const char *program_name	INIT(NULL);
EXTERN	const char jsonl_header[]	INIT("Accept: application/x-ndjson");
EXTERN	const char status_noerror[]	INIT("NOERROR");
EXTERN	const char status_error[]	INIT("ERROR");
EXTERN	pdns_system_ct psys		INIT(NULL);
EXTERN	int debug_level			INIT(0);
EXTERN	bool donotverify		INIT(false);
EXTERN	bool quiet			INIT(false);
EXTERN	present_e presentation		INIT(pres_json);
EXTERN	present_t presenter		INIT(NULL);
EXTERN	struct timeval startup_time	INIT({});
EXTERN	int exit_code			INIT(0);
EXTERN	long curl_ipresolve		INIT(CURL_IPRESOLVE_WHATEVER);

#undef INIT
#undef EXTERN

/* maximum length of a regular expression or glob or exclusion */
#define MAX_VALUE_LEN 4096

__attribute__((noreturn)) void my_exit(int);
__attribute__((noreturn)) void my_panic(bool, const char *);

#endif /*GLOBALS_H_INCLUDED*/
