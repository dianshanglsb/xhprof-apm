/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2017 Xinhui Long
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>

#if __APPLE__
#include <mach/mach_init.h>
#include <mach/mach_time.h>
#endif

#include "ext/standard/info.h"
#include "php_xhprof_apm.h"
#include "ext/pcre/php_pcre.h"
#include "ext/pdo/php_pdo_driver.h"
#include "ext/standard/php_rand.h"
#include "ext/json/php_json.h"
#include "main/SAPI.h"
#include "zend_smart_str.h" /* for smart_str */

/**
 * *********************
 * PHP EXTENSION GLOBALS
 * *********************
 */
/* List of functions implemented/exposed by xhprof */
zend_function_entry xhprof_apm_functions[] = {
	{NULL, NULL, NULL}
};

ZEND_DECLARE_MODULE_GLOBALS(apm)

/* Callback functions for the xhprof_apm extension */
zend_module_entry xhprof_apm_module_entry = {
	STANDARD_MODULE_HEADER,
	"xhprof_apm",                        /* Name of the extension */
	xhprof_apm_functions,                /* List of functions exposed */
	PHP_MINIT(xhprof_apm),               /* Module init callback */
	PHP_MSHUTDOWN(xhprof_apm),           /* Module shutdown callback */
	PHP_RINIT(xhprof_apm),               /* Request init callback */
	PHP_RSHUTDOWN(xhprof_apm),           /* Request shutdown callback */
	PHP_MINFO(xhprof_apm),               /* Module info callback */
	XHPROF_APM_VERSION,
	PHP_MODULE_GLOBALS(apm),   /* globals descriptor */
	PHP_GINIT(apm),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

PHP_INI_BEGIN()

PHP_INI_ENTRY("xhprof_apm.config_ini", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.export", "php", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.php_file", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.curl_uri", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.curl_timeout_ms", "1000", PHP_INI_ALL, NULL)

PHP_INI_END()

/* Init module */
ZEND_GET_MODULE(xhprof_apm)

PHP_GINIT_FUNCTION(apm)
{
	apm_globals->enabled = 0;
	apm_globals->ever_enabled = 0;
	apm_globals->xhprof_flags = 0;
	apm_globals->entries = NULL;
    apm_globals->root = NULL;
    apm_globals->trace_callbacks = NULL;
    apm_globals->ignored_functions = NULL;
	apm_globals->debug = 0;
}

/**
 * Module init callback.
 *
 * @author cjiang
 */
PHP_MINIT_FUNCTION(xhprof_apm)
{
	int i;

	REGISTER_INI_ENTRIES();

	hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

    ZVAL_UNDEF(&APM_G(stats_count));
    APM_G(trace_callbacks) = NULL;

	/* no free hp_entry_t structures to start with */
	APM_G(entry_free_list) = NULL;

	for (i = 0; i < 256; i++) {
		APM_G(func_hash_counters[i]) = 0;
	}

    APM_STORE_ZEND_HANDLE();

#if defined(DEBUG)
    /* To make it random number generator repeatable to ease testing. */
    srand(0);
#endif

	return SUCCESS;
}

/**
 * Module shutdown callback.
 */
PHP_MSHUTDOWN_FUNCTION(xhprof_apm)
{
	/* free any remaining items in the free list */
	hp_free_the_free_list();

    APM_RESTORE_ZEND_HANDLE();

	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS)
{
	REGISTER_LONG_CONSTANT("APM_FLAGS_NO_BUILTINS",
						   APM_FLAGS_NO_BUILTINS,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_CPU",
						   APM_FLAGS_CPU,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_MEMORY",
						   APM_FLAGS_MEMORY,
						   CONST_CS | CONST_PERSISTENT);
}

/**
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 *
 * @author cjiang
 */
static inline uint8 hp_inline_hash(char * str)
{
	ulong h = 5381;
	uint i = 0;
	uint8 res = 0;

	while (*str) {
		h += (h << 5);
		h ^= (ulong) *str++;
	}

	for (i = 0; i < sizeof(ulong); i++) {
		res += ((uint8 *)&h)[i];
	}
	return res;
}

static void hp_parse_options_from_config(zval *config)
{
	hp_clean_profiler_options_state();

	if (config == NULL) {
		return;
	}

	zval *pzval;
	pzval = hp_zval_at_key("ignored", config);
	/* Set up filter of functions which may be ignored during profiling */
	APM_G(ignored_functions) = hp_ignored_functions_init(hp_strings_in_zval(pzval));
}

static hp_ignored_function_map *hp_ignored_functions_init(char **names)
{
	hp_clean_profiler_options_state();

	if (names == NULL) {
		return NULL;
	}

	hp_ignored_function_map *function_map;

	function_map = emalloc(sizeof(hp_ignored_function_map));
	function_map->names = names;

	memset(function_map->filter, 0, APM_IGNORED_FUNCTION_FILTER_SIZE);

	int i = 0;
	for(; names[i] != NULL; i++) {
		char *str  = names[i];
		uint8 hash = hp_inline_hash(str);
		int   idx  = INDEX_2_BYTE(hash);
		function_map->filter[idx] |= INDEX_2_BIT(hash);
	}

	return function_map;
}

static void hp_ignored_functions_clear(hp_ignored_function_map *map)
{
	if (map == NULL) {
		return;
	}

	hp_array_del(map->names);
	map->names = NULL;

	memset(map->filter, 0, APM_IGNORED_FUNCTION_FILTER_SIZE);
	efree(map);
}

/**
 * Check if function collides in filter of functions to be ignored.
 *
 * @author mpal
 */
int hp_ignored_functions_filter_collision(hp_ignored_function_map *map, uint8 hash)
{
	uint8 mask = INDEX_2_BIT(hash);
	return map->filter[INDEX_2_BYTE(hash)] & mask;
}

/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state()
{
	/* Setup globals */
	if (!APM_G(ever_enabled)) {
		APM_G(ever_enabled)  = 1;
		APM_G(entries) = NULL;
	}

    /* Init stats_count */
    if (Z_TYPE(APM_G(stats_count)) != IS_UNDEF) {
        zval_ptr_dtor(&APM_G(stats_count));
    }

	array_init(&APM_G(stats_count));

	hp_init_trace_callbacks();
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
void hp_clean_profiler_state()
{
	/* Clear globals */
    if (Z_TYPE(APM_G(stats_count)) != IS_UNDEF) {
        zval_ptr_dtor(&APM_G(stats_count));
    }

    ZVAL_UNDEF(&APM_G(stats_count));

	APM_G(entries) = NULL;
	APM_G(ever_enabled) = 0;
	APM_G(debug) = 0;

    hp_clean_profiler_options_state();
}

static void hp_clean_profiler_options_state()
{
    /* Delete the array storing ignored function names */
    hp_ignored_functions_clear(APM_G(ignored_functions));
    APM_G(ignored_functions) = NULL;

    if (APM_G(trace_callbacks)) {
        zend_hash_destroy(APM_G(trace_callbacks));
        FREE_HASHTABLE(APM_G(trace_callbacks));
        APM_G(trace_callbacks) = NULL;
    }
}
/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
static char* hp_get_entry_name(hp_entry_t *entry)
{
	char *result_buf;

	/* Add '@recurse_level' if required */
	/* NOTE:  Dont use snprintf's return val as it is compiler dependent */
	if (entry->rlvl_hprof) {
		spprintf(&result_buf, 0, "%s@%d", entry->name_hprof, entry->rlvl_hprof);
	}
	else {
		spprintf(&result_buf, 0, "%s", entry->name_hprof);
	}

	return result_buf;
}

/**
 * Check if this entry should be ignored, first with a conservative Bloomish
 * filter then with an exact check against the function names.
 *
 * @author mpal
 */
static inline int hp_ignore_entry_work(uint8 hash_code, char *curr_func)
{
	if (APM_G(ignored_functions) == NULL) {
		return 0;
	}

	hp_ignored_function_map *map = APM_G(ignored_functions);

	if (hp_ignored_functions_filter_collision(map, hash_code)) {
		int i = 0;
		for (; map->names[i] != NULL; i++) {
			char *name = map->names[i];
			if (strcmp(curr_func, name) == 0) {
				return 1;
			}
		}
	}

    return 0;
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And  "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 *
 * @author kannan, veeve
 */
static char* hp_get_function_stack(hp_entry_t *entry, int level)
{
	char *result_buf, *curr_result, *prev_result;

	/* End recursion if we dont need deeper levels or we dont have any deeper
     * levels */
	if (!entry->prev_hprof || (level <= 1)) {
		return hp_get_entry_name(entry);
	}

	/* Take care of all ancestors first */
	prev_result = hp_get_function_stack(entry->prev_hprof, level - 1);

	/* Append the delimiter */
# define    HP_STACK_DELIM        "==>"

	/* Add delimiter only if entry had ancestors */
	strcat(prev_result, HP_STACK_DELIM);

# undef     HP_STACK_DELIM

	curr_result = hp_get_entry_name(entry);

	/* Append the current function name */
	spprintf(&result_buf, 0, "%s%s", prev_result, curr_result);

	efree(prev_result);
	efree(curr_result);
	return result_buf;
}

static char *hp_concat_char(const char *s1, const char *s2, const char *seperator)
{
    char *result;
    spprintf(&result, 0, "%s%s%s", s1, seperator, s2);

    return result;
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static const char *hp_get_base_filename(const char *filename)
{
	const char *ptr;
	int   found = 0;

	if (!filename)
		return "";

	/* reverse search for "/" and return a ptr to the next char */
	for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--) {
		if (*ptr == '/') {
			found++;
		}
		if (found == 2) {
			return ptr + 1;
		}
	}

	/* no "/" char found, so return the whole string */
	return filename;
}

/**
 * Get the name of the current function. The name is qualified with
 * the class name if the function is in a class.
 *
 * @author kannan, hzhao
 */
static char *hp_get_function_name(zend_execute_data *execute_data)
{
    const char        *cls = NULL;
    char              *ret;
    zend_function     *curr_func;
    zend_string       *func = NULL;

	if (!execute_data) {
		return NULL;
	}

	/* shared meta data for function on the call stack */
	curr_func = execute_data->func;
	/* extract function name from the meta info */
	func = curr_func->common.function_name;

    if (!func) {
        return NULL;
    }

	if (curr_func->common.scope != NULL) {
		char* sep = "::";
		cls = curr_func->common.scope->name->val;
		ret = hp_concat_char(cls, func->val, sep);
	} else {
        ret = estrdup(ZSTR_VAL(func));
	}

	return ret;
}

/**
 * Free any items in the free list.
 */
static void hp_free_the_free_list()
{
	hp_entry_t *p = APM_G(entry_free_list);
	hp_entry_t *cur;

	while (p) {
		cur = p;
		p = p->prev_hprof;
		free(cur);
	}
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry()
{
	hp_entry_t *p;

	p = APM_G(entry_free_list);

	if (p) {
		APM_G(entry_free_list) = p->prev_hprof;
		return p;
	} else {
		return (hp_entry_t *)malloc(sizeof(hp_entry_t));
	}
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 *
 * @author kannan
 */
static void hp_fast_free_hprof_entry(hp_entry_t *p)
{
	/* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
	p->prev_hprof = APM_G(entry_free_list);
	APM_G(entry_free_list) = p;
}

/**
 * Increment the count of the given stat with the given count
 * If the stat was not set before, inits the stat to the given count
 *
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  count    Value of the stat to incr by
 * @return void
 * @author kannan
 */
void hp_inc_count(zval *counts, char *name, long count)
{
	HashTable *ht;
	zval *data, val;

	if (!counts) {
		return;
	}

	ht = HASH_OF(counts);

	if (!ht) {
		return;
	}

	data = zend_hash_str_find(ht, name, strlen(name));

	if (data) {
		ZVAL_LONG(data, Z_LVAL_P(data) + count);
	} else {
		ZVAL_LONG(&val, count);
		zend_hash_str_update(ht, name, strlen(name), &val);
	}
}

/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get time stamp counter (TSC) value via 'rdtsc' instruction.
 *
 * @return 64 bit unsigned integer
 * @author cjiang
 */
static inline uint64 cycle_timer()
{
#if defined(__APPLE__) && defined(__MACH__)
    return mach_absolute_time();
#else
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000 * 1000 * 1000 + s.tv_nsec;
#endif
}

/**
 * Get the current real CPU clock timer
 */
static uint64 cpu_timer()
{
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    struct timespec s;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &s);

	return s.tv_sec * 1000 * 1000 * 1000 + s.tv_nsec;
#else
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);

	return 1000 * (
		(ru.ru_utime.tv_sec  + ru.ru_stime.tv_sec ) * 1000 * 1000 + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec)
	);
#endif
}

/**
 * ************************************
 * XHPROF BEGIN FUNCTION CALLBACKS
 * ************************************
 */

/**
 * XHPROF_MODE_HIERARCHICAL's begin function callback
 *
 * @author kannan
 */
void hp_mode_hier_beginfn_cb(hp_entry_t **entries, hp_entry_t *current)
{
	hp_entry_t   *p;
    /* This symbol's recursive level */
    int    recurse_level = 0;
    /* Get start tsc counter */
	current->tsc_start = cycle_timer();

    if (APM_G(func_hash_counters[current->hash_code]) > 0) {
        /* Find this symbols recurse level */
        for(p = (*entries); p; p = p->prev_hprof) {
            if (!strcmp(current->name_hprof, p->name_hprof)) {
                recurse_level = (p->rlvl_hprof) + 1;
                break;
            }
        }
    }

    APM_G(func_hash_counters[current->hash_code])++;

    /* Init current function's recurse level */
    current->rlvl_hprof = recurse_level;

	/* Get CPU usage */
	if (APM_G(xhprof_flags) & APM_FLAGS_CPU) {
        current->cpu_start = cpu_timer();
	}

	/* Get memory usage */
	if (APM_G(xhprof_flags) & APM_FLAGS_MEMORY) {
		current->mu_start_hprof  = zend_memory_usage(0);
		current->pmu_start_hprof = zend_memory_peak_usage(0);
	}
}

/**
 * **********************************
 * XHPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * XHPROF_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
void hp_mode_hier_endfn_cb(hp_entry_t **entries)
{
	hp_entry_t   *top = (*entries);
	zval            *counts;
	char             *symbol;
	long int         mu_end;
	long int         pmu_end;
    double           wt, cpu;

	/* Get end tsc counter */
	wt = cycle_timer() - top->tsc_start;

	/* Get the stat array */
    symbol = hp_get_function_stack(top, 2);

	counts = zend_hash_str_find(Z_ARRVAL(APM_G(stats_count)), symbol, strlen(symbol));

	if (counts == NULL) {
        zval count_val;
        array_init(&count_val);
        counts = zend_hash_str_update(Z_ARRVAL(APM_G(stats_count)), symbol, strlen(symbol), &count_val);
	}

	/* Bump stats in the counts hashtable */
	hp_inc_count(counts, "ct", 1);
	hp_inc_count(counts, "wt", wt);

	if (APM_G(xhprof_flags) & APM_FLAGS_CPU) {
        cpu = cpu_timer() - top->cpu_start;

		/* Bump CPU stats in the counts hashtable */
		hp_inc_count(counts, "cpu", cpu);
	}

	if (APM_G(xhprof_flags) & APM_FLAGS_MEMORY) {
		/* Get Memory usage */
		mu_end  = zend_memory_usage(0);
		pmu_end = zend_memory_peak_usage(0);

		/* Bump Memory stats in the counts hashtable */
		hp_inc_count(counts, "mu",  mu_end - top->mu_start_hprof);
		hp_inc_count(counts, "pmu", pmu_end - top->pmu_start_hprof);
	}

	efree(symbol);
}

/**
 * ***************************
 * PHP EXECUTE/COMPILE PROXIES
 * ***************************
 */

/**
 * XHProf enable replaced the zend_execute function with this
 * new execute function. We can do whatever profiling we need to
 * before and after calling the actual zend_execute().
 *
 * @author hzhao, kannan
 */
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data)
{
	char          *func = NULL;
	int hp_profile_flag = 1;

    if (!APM_G(enabled)) {
		_zend_execute_ex(execute_data);
        return;
    }

	func = hp_get_function_name(execute_data);
	if (!func) {
		_zend_execute_ex(execute_data);
		return;
	}

	zend_execute_data *real_execute_data = execute_data->prev_execute_data;
	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, real_execute_data);

	_zend_execute_ex(execute_data);

	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}
	efree(func);
}

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 *
 * @author hzhao, kannan
 */

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
	char             *func = NULL;
	int    hp_profile_flag = 1;

    if (!APM_G(enabled) || (APM_G(xhprof_flags) & APM_FLAGS_NO_BUILTINS) > 0) {
		execute_internal(execute_data, return_value);
		return;
    }

	func = hp_get_function_name(execute_data);

	if (func) {
		BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, execute_data);
	}

	if (!_zend_execute_internal) {
		/* no old override to begin with. so invoke the builtin's implementation  */
		execute_internal(execute_data, return_value);
	} else {
		/* call the old override */
		_zend_execute_internal(execute_data, return_value);
	}

	if (func) {
		if (APM_G(entries)) {
			END_PROFILING(&APM_G(entries), hp_profile_flag);
		}
		efree(func);
	}

}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 *
 * @author kannan, hzhao
 */
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type)
{
    if (!APM_G(enabled)) {
        return _zend_compile_file(file_handle, type);
    }

	const char     *filename;
	char           *func;
	int             len;
	zend_op_array  *ret;
	int             hp_profile_flag = 1;

	filename = hp_get_base_filename(file_handle->filename);
	len      = strlen("load") + strlen(filename) + 3;
	func      = (char *)emalloc(len);
	snprintf(func, len, "load::%s", filename);

	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, NULL);
	ret = _zend_compile_file(file_handle, type);
	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

	efree(func);
	return ret;
}

/**
 * Proxy for zend_compile_string(). Used to profile PHP eval compilation time.
 */
ZEND_DLEXPORT zend_op_array* hp_compile_string(zval *source_string, char *filename)
{
    if (!APM_G(enabled)) {
        return _zend_compile_string(source_string, filename);
    }

	char          *func;
	int            len;
	zend_op_array *ret;
	int            hp_profile_flag = 1;

	len  = strlen("eval") + strlen(filename) + 3;
	func = (char *)emalloc(len);
	snprintf(func, len, "eval::%s", filename);

	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, NULL);
	ret = _zend_compile_string(source_string, filename);
	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

	efree(func);
	return ret;
}

/**
 * **************************
 * MAIN XHPROF CALLBACKS
 * **************************
 */

/**
 * This function gets called once when xhprof gets enabled.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static void hp_begin(long xhprof_flags)
{
	if (!APM_G(enabled)) {
		int hp_profile_flag = 1;

		APM_G(enabled)      = 1;
		APM_G(xhprof_flags) = (uint32)xhprof_flags;

		/* one time initializations */
		hp_init_profiler_state();

        APM_G(root) = estrdup(ROOT_SYMBOL);
		/* start profiling from fictitious main() */
		BEGIN_PROFILING(&APM_G(entries), APM_G(root), hp_profile_flag, NULL);
	}
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end()
{
    /* Bail if not ever enabled */
    if (!APM_G(ever_enabled)) {
        return;
    }

    /* Stop profiler if enabled */
    if (APM_G(enabled)) {
        hp_stop();
    }

    /* Clean up state */
	hp_clean_profiler_state();
}

/**
 * Called from xhprof_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop()
{
	int   hp_profile_flag = 1;

	/* End any unfinished calls */
	while (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

    if (APM_G(root)) {
        efree(APM_G(root));
        APM_G(root) = NULL;
    }

	/* Stop profiling */
	APM_G(enabled) = 0;
}

/**
 * *****************************
 * XHPROF ZVAL UTILITY FUNCTIONS
 * *****************************
 */

/** Look in the PHP assoc array to find a key and return the zval associated
 *  with it.
 *
 *  @author mpal
 **/
static zval *hp_zval_at_key(char *key, zval *values)
{
	zval *result;

	if (Z_TYPE_P(values) == IS_ARRAY) {
		uint len = strlen(key);

		result = zend_hash_str_find(Z_ARRVAL_P(values), key, len);
	} else {
		result = NULL;
	}

	return result;
}

/** Convert the PHP array of strings to an emalloced array of strings. Note,
 *  this method duplicates the string data in the PHP array.
 *
 *  @author mpal
 **/
static char **hp_strings_in_zval(zval *values)
{
	char   **result;
	size_t   count;
	size_t   ix = 0;

	if (!values) {
		return NULL;
	}

	if (Z_TYPE_P(values) == IS_ARRAY) {
		HashTable *ht;
		zend_ulong num_key;
		zend_string *key;
		zval *val;

		ht    = Z_ARRVAL_P(values);
		count = zend_hash_num_elements(ht);

		if ((result = (char**)emalloc(sizeof(char*) * (count + 1))) == NULL) {
			return result;
		}

		ZEND_HASH_FOREACH_KEY_VAL(ht, num_key, key, val) {
			if (!key) {
				if (Z_TYPE_P(val) == IS_STRING && strcmp(Z_STRVAL_P(val), ROOT_SYMBOL) != 0) {
					/* do not ignore "main" */
					result[ix] = estrdup(Z_STRVAL_P(val));
					ix++;
				}
			}
		} ZEND_HASH_FOREACH_END();
	} else if (Z_TYPE_P(values) == IS_STRING) {
		if ((result = (char**)emalloc(sizeof(char*) * 2)) == NULL) {
			return result;
		}
		result[0] = estrdup(Z_STRVAL_P(values));
		ix = 1;
	} else {
		result = NULL;
	}

	/* NULL terminate the array */
	if (result != NULL) {
		result[ix] = NULL;
	}

	return result;
}

/* Free this memory at the end of profiling */
static inline void hp_array_del(char **name_array)
{
	if (name_array != NULL) {
		int i = 0;
		for(; name_array[i] != NULL && i < APM_MAX_IGNORED_FUNCTIONS; i++) {
			efree(name_array[i]);
		}
		efree(name_array);
	}
}

void hp_ini_parser_cb(zval *key, zval *value, zval *index, int callback_type, zval *arr)
{
	zval element;
	switch (callback_type) {
		case ZEND_INI_PARSER_ENTRY :
			{
				zval *pzval, *dst;
				char *skey, *seg, *ptr;

				if (!value) {
					break;
				}

				dst = arr;
				skey = estrndup(Z_STRVAL_P(key), Z_STRLEN_P(key));
				if ((seg = php_strtok_r(skey, ".", &ptr))) {
					do {
						char *real_key = seg;
						seg = php_strtok_r(NULL, ".", &ptr);
						if ((pzval = zend_symtable_str_find(Z_ARRVAL_P(dst), real_key, strlen(real_key))) == NULL) {
							if (seg) {
								zval tmp;
								array_init(&tmp);
								pzval = zend_symtable_str_update(Z_ARRVAL_P(dst),
																 real_key, strlen(real_key), &tmp);
							} else {
								ZVAL_COPY(&element, value);
								zend_symtable_str_update(Z_ARRVAL_P(dst),
														 real_key, strlen(real_key), &element);
								break;
							}
						} else {
							SEPARATE_ZVAL(pzval);
							if (IS_ARRAY != Z_TYPE_P(pzval)) {
								if (seg) {
									zval tmp;
									array_init(&tmp);
									pzval = zend_symtable_str_update(Z_ARRVAL_P(dst),
																	 real_key, strlen(real_key), &tmp);
								} else {
									ZVAL_DUP(&element, value);
									zend_symtable_str_update(Z_ARRVAL_P(dst),
															 real_key, strlen(real_key), &element);
								}
							}
						}
						dst = pzval;
					} while (seg);
				}
				efree(skey);
			}
		break;

		case ZEND_INI_PARSER_POP_ENTRY:
			{
				zval hash, *find_hash, *dst;

				if (!value) {
					break;
				}

				if (!(Z_STRLEN_P(key) > 1 && Z_STRVAL_P(key)[0] == '0')
					&& is_numeric_string(Z_STRVAL_P(key), Z_STRLEN_P(key), NULL, NULL, 0) == IS_LONG) {
					zend_ulong skey = (zend_ulong)zend_atol(Z_STRVAL_P(key), Z_STRLEN_P(key));
					if ((find_hash = zend_hash_index_find(Z_ARRVAL_P(arr), skey)) == NULL) {
						array_init(&hash);
						find_hash = zend_hash_index_update(Z_ARRVAL_P(arr), skey, &hash);
					}
				} else {
					char *seg, *ptr;
					char *skey = estrndup(Z_STRVAL_P(key), Z_STRLEN_P(key));

					dst = arr;
					if ((seg = php_strtok_r(skey, ".", &ptr))) {
						while (seg) {
							if ((find_hash = zend_symtable_str_find(Z_ARRVAL_P(dst), seg, strlen(seg))) == NULL) {
								array_init(&hash);
								find_hash = zend_symtable_str_update(Z_ARRVAL_P(dst),
																	 seg, strlen(seg), &hash);
							}
							dst = find_hash;
							seg = php_strtok_r(NULL, ".", &ptr);
						}
					} else {
						if ((find_hash = zend_symtable_str_find(Z_ARRVAL_P(dst), seg, strlen(seg))) == NULL) {
							array_init(&hash);
							find_hash = zend_symtable_str_update(Z_ARRVAL_P(dst), seg, strlen(seg), &hash);
						}
					}
					efree(skey);
				}

				if (Z_TYPE_P(find_hash) != IS_ARRAY) {
					zval_ptr_dtor(find_hash);
					array_init(find_hash);
				}

				ZVAL_DUP(&element, value);

				if (index && Z_STRLEN_P(index) > 0) {
					zend_symtable_update(Z_ARRVAL_P(find_hash), Z_STR_P(index), &element);
				} else {
					add_next_index_zval(find_hash, &element);
				}
			}
			break;

		case ZEND_INI_PARSER_SECTION:
			break;

	}
}

static char *hp_get_trace_callback(char* symbol, zend_execute_data *data)
{
    char *result;
    hp_trace_callback *callback;

	callback = (hp_trace_callback*)zend_hash_str_find(APM_G(trace_callbacks), symbol, strlen(symbol));
	if (callback) {
		result = (*callback)(symbol, data);
	} else {
		spprintf(&result, 0, "%s", symbol);
	}

    efree(symbol);

    return result;
}

zend_string *hp_pcre_match(char *pattern, int len, zval *data, zend_ulong idx)
{
	zval matches, *match;
	zval rsubparts, *subparts;
	pcre_cache_entry *pce_regexp;
	zend_string *pattern_str, *result = NULL;

	pattern_str = zend_string_init(pattern, len, 0);
	if ((pce_regexp = pcre_get_compiled_regex_cache(pattern_str)) == NULL) {
		zend_string_release(pattern_str);
		return NULL;
	}

	ZVAL_NULL(&rsubparts);
	subparts = &rsubparts;

	php_pcre_match_impl(pce_regexp, Z_STRVAL_P(data), Z_STRLEN_P(data), &matches, subparts /* subpats */,
						0/* global */, 0/* ZEND_NUM_ARGS() >= 4 */, 0/*flags PREG_OFFSET_CAPTURE*/, 0/* start_offset */);

	if (zend_hash_num_elements(Z_ARRVAL_P(subparts))) {
		match = zend_hash_index_find(Z_ARRVAL_P(subparts), idx);

		if (match != NULL) {
			result = zend_string_init(Z_STRVAL_P(match), Z_STRLEN_P(match), 0);
		}
	}

	zend_string_release(pattern_str);
	zval_ptr_dtor(&matches);
	zval_ptr_dtor(subparts);

	return result;
}

zend_string *hp_pcre_replace(char *pattern, int len, zval *repl, zval *data, int limit)
{
	zval subparts;
	pcre_cache_entry *pce_regexp;
	zend_string *pattern_str, *replace;

	pattern_str = zend_string_init(pattern, len, 0);

	if ((pce_regexp = pcre_get_compiled_regex_cache(pattern_str)) == NULL) {
		return NULL;
	}

    zend_string_release(pattern_str);

#if PHP_VERSION_ID < 70200
	if (Z_TYPE_P(data) != IS_STRING) {
		convert_to_string(data);
	}

	replace = php_pcre_replace_impl(pce_regexp, NULL, Z_STRVAL_P(repl), Z_STRLEN_P(repl), data, 0, limit, 0);
#elif PHP_VERSION_ID >= 70200
    zend_string *z_str = zval_get_string(data);

    replace = php_pcre_replace_impl(pce_regexp, NULL, Z_STRVAL_P(repl), Z_STRLEN_P(repl), z_str, limit, 0);

    zend_string_release(z_str);
#endif

	return replace;
}

char* hp_trace_callback_pdo_connect(char *symbol, zend_execute_data *data)
{
	char *result;
	zend_string *match;
	smart_str match_str = {0};
	zval *dsn = ZEND_CALL_ARG(data, 1);

	if ((match = hp_pcre_match(ZEND_STRL("(^(mysql|sqlite|pgsql|odbc|oci):)"), dsn, 1))) {
		smart_str_appendl(&match_str, ZSTR_VAL(match), ZSTR_LEN(match));

		zend_string_release(match);

		if ((match = hp_pcre_match(ZEND_STRL("(host=([^;\\s]+))"), dsn, 1))) {
			smart_str_appendc(&match_str, '@');
			smart_str_appendl(&match_str, ZSTR_VAL(match), ZSTR_LEN(match));

			zend_string_release(match);
		}

		if ((match = hp_pcre_match(ZEND_STRL("(port=([^;\\s]+))"), dsn, 1))) {
			smart_str_appendc(&match_str, ':');
			smart_str_appendl(&match_str, ZSTR_VAL(match), ZSTR_LEN(match));

			zend_string_release(match);
		} else {
			smart_str_appendc(&match_str, ':');
			smart_str_append_long(&match_str, 3306);
		}

		if ((match = hp_pcre_match(ZEND_STRL("(dbname=([^;\\s]+))"), dsn, 1))) {
			smart_str_appendc(&match_str, '/');
			smart_str_appendl(&match_str, ZSTR_VAL(match), ZSTR_LEN(match));
		}

		spprintf(&result, 0, "%s#%s", symbol, ZSTR_VAL(match_str.s));

		zend_string_release(match);
		smart_str_free(&match_str);
	} else {
		spprintf(&result, 0, "%s", symbol);
	}

	return result;
}

char* hp_trace_callback_sql_query(char *symbol, zend_execute_data *data)
{
    char *result;

    if (strcmp(symbol, "mysqli_query") == 0) {
        zval *arg = ZEND_CALL_ARG(data, 2);
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(arg));
    } else {
        zval *arg = ZEND_CALL_ARG(data, 1);
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(arg));
    }

    return result;
}

char* hp_trace_callback_pdo_statement_execute(char *symbol, zend_execute_data *data)
{
	char *result;
    zend_class_entry *pdo_ce;
	zval *object = (data->This.value.obj) ? &(data->This) : NULL;
    zval *query_string, *arg, copy_query;

	if (object != NULL) {
        query_string = zend_read_property(pdo_ce, object, ZEND_STRL("queryString"), 0, NULL);

        if (query_string == NULL || Z_TYPE_P(query_string) != IS_STRING) {
            spprintf(&result, 0, "%s", symbol);
            return result;
        }

#ifndef HAVE_PCRE
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(query_string));
        return result;
#endif

        arg = ZEND_CALL_ARG(data, 1);
        if (Z_TYPE_P(arg) != IS_ARRAY) {
            spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(query_string));
            return result;
        }

        zend_string *pattern_str = NULL;

		ZVAL_STR(&copy_query, zval_get_string(query_string));

        if (strstr(Z_STRVAL(copy_query), "?") != NULL) {
            pattern_str = zend_string_init("([\?])", sizeof("([\?])") - 1, 0);
        } else if (strstr(Z_STRVAL(copy_query), ":") != NULL) {
            pattern_str = zend_string_init("(:([^\\s]+))", sizeof("(:([^\\s]+))") - 1, 0);
        }

        if (pattern_str) {
			zend_string *match;
			if ((match = hp_pcre_match(ZSTR_VAL(pattern_str), ZSTR_LEN(pattern_str), &copy_query, 0))) {
				zend_ulong num_key;
				zend_string *key;
				zval *val;
				zend_string *replace;

				ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(arg), num_key, key, val)
				{
					replace = hp_pcre_replace(ZSTR_VAL(pattern_str), ZSTR_LEN(pattern_str), &copy_query, val, 1);

					if (replace != NULL) {
						zval_ptr_dtor(&copy_query);
						ZVAL_STR(&copy_query, replace);
					}

				}ZEND_HASH_FOREACH_END();

				zend_string_release(match);
			}

            zend_string_release(pattern_str);

            spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL(copy_query));

        } else {
            spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL(copy_query));
        }

		zval_ptr_dtor(&copy_query);

	} else {
		spprintf(&result, 0, "%s", symbol);
	}

    return result;
}

char* hp_trace_callback_curl_exec(char *symbol, zend_execute_data *data)
{
    char *result;
    zval func, retval, *option;
    zval *arg = ZEND_CALL_ARG(data, 1);

    if (arg == NULL || Z_TYPE_P(arg) != IS_RESOURCE) {
        spprintf(&result, 0, "%s", symbol);
        return result;
    }

    zval params[1];
	ZVAL_COPY(&params[0], arg);
    ZVAL_STRING(&func, "curl_getinfo");

	zend_fcall_info fci = {
		size: sizeof(zend_fcall_info),
#if PHP_VERSION_ID < 70100
		function_table: EG(function_table),
#endif
		function_name: func,
#if PHP_VERSION_ID < 70100
		symbol_table: NULL,
#endif
        retval: &retval,
        params: &params,
        object: NULL,
		no_separation: 1,
        param_count: 1
	};

    if (zend_call_function(&fci, NULL) == FAILURE) {
		spprintf(&result, 0, "%s#%s", symbol, "unknown");
    } else {
		option = zend_hash_str_find(Z_ARRVAL(retval), ZEND_STRL("url"));
		spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(option));
	}

	efree(symbol);

    return result;
}

static void hp_init_trace_callbacks()
{
	hp_trace_callback callback;

	APM_G(trace_callbacks) = NULL;
	ALLOC_HASHTABLE(APM_G(trace_callbacks));

	if (!APM_G(trace_callbacks)) {
		return;
	}

	zend_hash_init(APM_G(trace_callbacks), 16, NULL, NULL, 0);

	callback = hp_trace_callback_sql_query;
    register_trace_callback("PDO::exec", callback);
    register_trace_callback("PDO::query", callback);
    register_trace_callback("mysql_query", callback);
    register_trace_callback("mysqli_query", callback);
    register_trace_callback("mysqli::query", callback);

    callback = hp_trace_callback_pdo_statement_execute;
    register_trace_callback("PDOStatement::execute", callback);

    callback = hp_trace_callback_curl_exec;
    register_trace_callback("curl_exec", callback);

    callback = hp_trace_callback_pdo_connect;
	register_trace_callback("PDO::__construct", callback);
}

static zval *hp_request_query_ex(uint type, zend_bool fetch_type, void *name, size_t len)
{
    zval *carrier = NULL, *ret;

    zend_bool jit_initialization = PG(auto_globals_jit);

    switch (type) {
        case TRACK_VARS_POST:
        case TRACK_VARS_GET:
        case TRACK_VARS_FILES:
        case TRACK_VARS_COOKIE:
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_ENV:
            if (jit_initialization) {
                zend_string *env_str = zend_string_init("_ENV", sizeof("_ENV") - 1, 0);
                zend_is_auto_global(env_str);
                zend_string_release(env_str);
            }
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_SERVER:
            if (jit_initialization) {
                zend_string *server_str = zend_string_init("_SERVER", sizeof("_SERVER") - 1, 0);
                zend_is_auto_global(server_str);
                zend_string_release(server_str);
            }
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_REQUEST:
            if (jit_initialization) {
                zend_string *request_str = zend_string_init("_REQUEST", sizeof("_REQUEST") - 1, 0);
                zend_is_auto_global(request_str);
                zend_string_release(request_str);
            }
            carrier = zend_hash_str_find(&EG(symbol_table), ZEND_STRL("_REQUEST"));
            break;
        default:
            break;
    }

    if (!carrier) {
        return NULL;
    }

    if (!name) {
        return carrier;
    }

    if (EXPECTED(fetch_type)) {
        if ((ret = zend_hash_find(Z_ARRVAL_P(carrier), (zend_string *)name)) == NULL) {
            return NULL;
        }
    } else {
        if ((ret = zend_hash_str_find(Z_ARRVAL_P(carrier), (char *)name, len)) == NULL) {
            return NULL;
        }
    }
    return ret;
}


int hp_get_export_data(zval *data, int debug, zval *result)
{
	zval meta;
	zval *server, *uri, *ssl, *server_name, *get;
	zval repl, pzurl;
	char *scheme, *url;

	array_init(&meta);

	server = hp_request_query(TRACK_VARS_SERVER, NULL);
	uri = hp_request_query_str(TRACK_VARS_SERVER, "REQUEST_URI", strlen("REQUEST_URI"));
	ssl = hp_request_query_str(TRACK_VARS_SERVER, "HTTPS", strlen("HTTPS"));
	server_name = hp_request_query_str(TRACK_VARS_SERVER, "SERVER_NAME", strlen("SERVER_NAME"));
	get = hp_request_query(TRACK_VARS_GET, NULL);

    Z_TRY_ADDREF_P(server);
    Z_TRY_ADDREF_P(get);

	if (ssl != NULL && Z_TYPE_P(ssl) != IS_NULL) {
		spprintf(&scheme, 0, "%s", "https");
	} else {
		spprintf(&scheme, 0, "%s", "http");
	}

	if (server_name != NULL && Z_TYPE_P(server_name) == IS_STRING && Z_TYPE_P(uri) != NULL) {
		spprintf(&url, 0, "%s://%s%s", scheme, Z_STRVAL_P(server_name), Z_STRVAL_P(uri));
	} else {
		spprintf(&url, 0, "%s", "unknown");
	}

	ZVAL_EMPTY_STRING(&repl);
	ZVAL_STRING(&pzurl, url);

	zend_string *simple_url = hp_pcre_replace("(=[^&]+)", sizeof("(=[^&]+)") - 1, &pzurl, &repl, -1);

	add_assoc_string_ex(&meta, "url", strlen("url"), url);
	add_assoc_string_ex(&meta, "simple_url", strlen("simple_url"), ZSTR_VAL(simple_url));
	add_assoc_long_ex(&meta, "request_date", strlen("request_date"), sapi_get_request_time());
	add_assoc_zval_ex(&meta, "SERVER", strlen("SERVER"), server);
	add_assoc_zval_ex(&meta, "GET", strlen("GET"), get);

	add_assoc_zval_ex(result, "meta", strlen("meta"), &meta);
	add_assoc_zval_ex(result, "profile", strlen("profile"), data);

	zval *root = hp_zval_at_key(ROOT_SYMBOL, data);
	zval *wt = hp_zval_at_key("wt", root);
	if (wt) {
		add_assoc_long_ex(result, "wt", strlen("wt"), Z_LVAL_P(wt));
	} else {
		add_assoc_long_ex(result, "wt", strlen("wt"), 0);
	}

	zval *cpu = hp_zval_at_key("cpu", root);
	if (cpu) {
		add_assoc_long_ex(result, "cpu", strlen("cpu"), Z_LVAL_P(cpu));
	} else {
		add_assoc_long_ex(result, "cpu", strlen("cpu"), 0);
	}

	zval *mu = hp_zval_at_key("mu", root);
	if (cpu) {
		add_assoc_long_ex(result, "mu", strlen("mu"), Z_LVAL_P(mu));
	} else {
		add_assoc_long_ex(result, "mu", strlen("mu"), 0);
	}

    add_assoc_long_ex(result, "debug", strlen("debug"), debug);

	efree(scheme);
	efree(url);

    zend_string_release(simple_url);

    zval_ptr_dtor(&repl);
    zval_ptr_dtor(&pzurl);

    return 1;
}

int hp_rshutdown_php(zval *data, int debug)
{
	char realpath[MAXPATHLEN];
    zend_string *path, *var_name;
    zend_file_handle file_handle;

    if (INI_STR("xhprof_apm.php_file") == NULL) {
        zval_ptr_dtor(data);
        return 0;
    }

    path = strpprintf(0, "%s", INI_STR("xhprof_apm.php_file"));
    if (VCWD_ACCESS(ZSTR_VAL(path), F_OK) == 0) {
        strcpy(realpath, ZSTR_VAL(path));
    } else {
        zend_string_release(path);
        zval *document_root = hp_request_query_str(TRACK_VARS_SERVER, "DOCUMENT_ROOT", sizeof("DOCUMENT_ROOT") - 1);
        path = strpprintf(0, "%s%c%s", Z_STRVAL_P(document_root), DEFAULT_SLASH, INI_STR("xhprof_apm.php_file"));

		if (!VCWD_REALPATH(ZSTR_VAL(path), realpath)) {
            zval_ptr_dtor(data);
            zend_string_release(path);
            return 0;
        }
    }

    struct stat sb;
    zend_op_array *op_array;
	zend_array *symbol_table;
	zval export_data, result;
    zend_execute_data *call;

    if (VCWD_STAT(realpath, &sb) == 0 && S_ISREG(sb.st_mode)) {
        if (VCWD_FOPEN(realpath, "r")) {
			file_handle.filename = realpath;
			file_handle.type = ZEND_HANDLE_FILENAME;
			file_handle.free_filename = 0;
			file_handle.opened_path = NULL;
            file_handle.handle.fp = NULL;

            op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);

            if (op_array) {
                ZVAL_UNDEF(&result);
                array_init(&export_data);

                if (file_handle.handle.stream.handle) {
                    if (!file_handle.opened_path) {
                        file_handle.opened_path = zend_string_copy(path);
                    }
                    zend_hash_add_empty_element(&EG(included_files), file_handle.opened_path);
                }

				symbol_table = emalloc(sizeof(zend_array));
				zend_hash_init(symbol_table, 8, NULL, ZVAL_PTR_DTOR, 0);
				zend_hash_real_init(symbol_table, 0);

				var_name = zend_string_init("_apm_export", sizeof("_apm_export") - 1, 0);
				hp_get_export_data(data, debug, &export_data);

				zend_hash_add_new(symbol_table, var_name, &export_data);

                call = zend_vm_stack_push_call_frame(ZEND_CALL_NESTED_CODE
#if PHP_VERSION_ID >= 70100
                        | ZEND_CALL_HAS_SYMBOL_TABLE
#endif
                        ,
                        (zend_function*)op_array, 0, op_array->scope, NULL);

                call->symbol_table = symbol_table;

                zend_init_execute_data(call, op_array, &result);

                ZEND_ADD_CALL_FLAG(call, ZEND_CALL_TOP);
                zend_execute_ex(call);
                zend_vm_stack_free_call_frame(call);

                destroy_op_array(op_array);
                efree(op_array);

                zval_ptr_dtor(&result);

                zend_string_release(var_name);
                zend_array_destroy(symbol_table);
            }

            zend_destroy_file_handle(&file_handle);
        }

        zend_string_release(path);
        return 1;
    } else {
        zval_ptr_dtor(data);
        zend_string_release(path);
        return 0;
    }
}

size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
}

int hp_rshutdown_curl(zval *data, int debug)
{
    zval export_data;
	char *uri = INI_STR("xhprof_apm.curl_uri");

	if (uri == NULL) {
        zval_ptr_dtor(data);
		return 0;
	}

    smart_str buf = {0};

    array_init(&export_data);
	hp_get_export_data(data, debug, &export_data);

	php_json_encode(&buf, &export_data, 0); /* options */

	smart_str_0(&buf);

	CURL *curl = curl_easy_init();
	if (curl) {
        CURLcode res;
		struct curl_slist *headers = NULL;
		double timeout = INI_FLT("xhprof_apm.curl_timeout_ms");

		headers = curl_slist_append(headers, "User-Agent: Xhprof-apm");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(curl, CURLOPT_URL, uri);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ZSTR_VAL(buf.s));
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (int)timeout);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (int)ceil(timeout / 1000));

		curl_easy_setopt(curl, CURLOPT_NETRC, 0);
		curl_easy_setopt(curl, CURLOPT_HEADER, 0);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		smart_str_free(&buf);
		curl_slist_free_all(headers);

		zval_ptr_dtor(&export_data);
		return 1;
	}

	smart_str_free(&buf);
	zval_ptr_dtor(&export_data);
	return 0;
}

/**
 * Request init callback. Nothing to do yet!
 */
PHP_RINIT_FUNCTION(xhprof_apm)
{
	int enable = 0;
	long flags = 0;

	if (SG(request_info).request_method) {
		zval *self_curl = hp_request_query_str(TRACK_VARS_SERVER, "HTTP_USER_AGENT", strlen("HTTP_USER_AGENT"));
        if (self_curl && Z_TYPE_P(self_curl) == IS_STRING && strcmp(Z_STRVAL_P(self_curl), "Xhprof-apm") == 0) {
			return SUCCESS;
		}

        zend_string *config_ini;
		char realpath[MAXPATHLEN];

        config_ini = strpprintf(0, "%s", INI_STR("xhprof_apm.config_ini"));
        if (VCWD_ACCESS(ZSTR_VAL(config_ini), F_OK) == 0) {
            strcpy(realpath, ZSTR_VAL(config_ini));
        } else {
            zend_string_release(config_ini);
            zval *document_root = hp_request_query_str(TRACK_VARS_SERVER, "DOCUMENT_ROOT", sizeof("DOCUMENT_ROOT") - 1);
            config_ini = strpprintf(0, "%s%c%s", Z_STRVAL_P(document_root), DEFAULT_SLASH, INI_STR("xhprof_apm.config_ini"));

            if (!VCWD_REALPATH(ZSTR_VAL(config_ini), realpath)) {
                zend_string_release(config_ini);
                return SUCCESS;
            }
        }

        zend_string_release(config_ini);

		struct stat sb;
		zend_file_handle fh;
		zval configs, *apm_config, *pzval;

		if (VCWD_STAT(realpath, &sb) == 0 && S_ISREG(sb.st_mode)) {
			if ((fh.handle.fp = VCWD_FOPEN(realpath, "r"))) {
				fh.filename = realpath;
				fh.type = ZEND_HANDLE_FP;
				fh.free_filename = 0;
				fh.opened_path = NULL;

				array_init(&configs);
				if (zend_parse_ini_file(&fh, 0, 0 /* ZEND_INI_SCANNER_NORMAL */,
										(zend_ini_parser_cb_t)hp_ini_parser_cb, &configs) == FAILURE) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}
			}
		} else {
			return SUCCESS;
		}

		apm_config = hp_zval_at_key("apm", &configs);
		if (!apm_config) {
			zval_ptr_dtor(&configs);
			return SUCCESS;
		}

		pzval = hp_zval_at_key("auto", apm_config);
		if (pzval) {
			convert_to_long(pzval);
			enable = Z_LVAL_P(pzval);
		}

		pzval = hp_zval_at_key("debug", apm_config);
		if (pzval) {
			convert_to_string(pzval);
			zval *zval_param = hp_request_query_str(TRACK_VARS_GET, Z_STRVAL_P(pzval), Z_STRLEN_P(pzval));
			if (zval_param) {
				APM_G(debug) = 1;
				enable = 1;
			}
		}

		if (!enable) {
			zval_ptr_dtor(&configs);
			return SUCCESS;
		}

		if (!APM_G(debug)) {
			pzval = hp_zval_at_key("rate", apm_config);
			if (pzval) {
				convert_to_long(pzval);
				int sample_rate = Z_LVAL_P(pzval);

				if (!sample_rate) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}

				long number = php_rand();
				RAND_RANGE(number, 0, 100, PHP_RAND_MAX);

				if (sample_rate < number) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}
			}
		}

		pzval = hp_zval_at_key("flags", apm_config);
		if (pzval) {
			convert_to_long(pzval);
			flags = Z_LVAL_P(pzval);
		}

		hp_parse_options_from_config(apm_config);
		hp_begin(flags);
		zval_ptr_dtor(&configs);
	}

	return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(xhprof_apm)
{
	if (APM_G(enabled)) {
		hp_stop();

        zval pzval;
		ZVAL_COPY(&pzval, &(APM_G(stats_count)));

		int debug = APM_G(debug);

		hp_end();

		char *export = INI_STR("xhprof_apm.export");
		if (strcmp(export, "php") == 0) {
			hp_rshutdown_php(&pzval, debug);
		} else if (strcmp(export, "curl") == 0) {
			hp_rshutdown_curl(&pzval, debug TSRMLS_CC);
		}
	}

	return SUCCESS;
}

/**
 * Module info callback. Returns the xhprof version.
 */
PHP_MINFO_FUNCTION(xhprof_apm)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "xhprof_apm support", "enabled");
    php_info_print_table_row(2, "Version", XHPROF_APM_VERSION);
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}