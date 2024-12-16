/* (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmo-pcap/osmo_pcap_server.h>

struct osmo_pcap_server *pcap_server;

extern bool check_localtime(const struct tm *last_write, const struct tm *tm, enum time_interval intv, unsigned int mod);

static void init_tm(struct tm *tm, int year, int month, int day, int hour, int min, int sec)
{
	memset(tm, 0, sizeof(*tm));
	tm->tm_sec = sec;
	tm->tm_min = min;
	tm->tm_hour = hour;
	tm->tm_mday = day;
	tm->tm_mon = month;
	tm->tm_year = year - 1900;
}

static enum time_interval test_intv;
static unsigned int test_mod;

static void _run_test(struct tm *last_write, const struct tm *now, bool exp_ret, const char *file, int line)
{
	char buf1[128], buf2[128];
	strftime(buf1, sizeof(buf1), "%Y-%m-%d_%H:%M:%S", last_write);
	strftime(buf2, sizeof(buf2), "%Y-%m-%d_%H:%M:%S", now);

	bool ret = check_localtime(last_write, now, test_intv, test_mod);
	fprintf(stderr, "{%s} check_localtime(last_write=%s, intv=%u, mod=%u) -> %s\n",
		buf2, buf1, test_intv, test_mod,
		ret ? "REOPEN" : "KEEP");
	*last_write = *now;
	if (ret != exp_ret)
		osmo_panic("%s:%d: ret (%d) != exp_ret (%d)", file, line, ret, exp_ret);
}
#define run_test(last_write, now, exp_ret) _run_test(last_write, now, exp_ret, __FILE__, __LINE__)


static void test_check_localtime_second_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_SEC;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, true);
	now.tm_sec++;
	run_test(&last_write, &now, true);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);

	now.tm_min += 1;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_min += 1;
	now.tm_sec += 23;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour += 3;
	now.tm_min += 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_year += 3;
	now.tm_mon += 2;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_second_mod_40(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_SEC;
	test_mod = 40;

	init_tm(&now, 2010, 2, 3, 4, 5, 0);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec = 1;
	run_test(&last_write, &now, false);
	now.tm_sec = 30;
	run_test(&last_write, &now, false);
	now.tm_sec = 39;
	run_test(&last_write, &now, false);
	now.tm_sec = 41;
	run_test(&last_write, &now, true);

	now.tm_min += 1;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_min += 1;
	now.tm_sec += 23;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour += 3;
	now.tm_min += 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_year += 3;
	now.tm_mon += 2;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_minute_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MIN;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);

	now.tm_min++;
	run_test(&last_write, &now, true);
	now.tm_min++;
	run_test(&last_write, &now, true);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);

	now.tm_min += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_min++;
	now.tm_sec = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, true);

	now.tm_min = 59;
	run_test(&last_write, &now, true);
	now.tm_hour++;
	now.tm_min = 0;
	run_test(&last_write, &now, true);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday += 20;
	run_test(&last_write, &now, true);
	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_minute_mod_2(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MIN;
	test_mod = 2;

	init_tm(&now, 2013, 2, 3, 4, 4, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);

	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, true);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);

	now.tm_min += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_min++;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, true);

	now.tm_min = 59;
	run_test(&last_write, &now, true);
	now.tm_hour++;
	now.tm_min = 0;
	run_test(&last_write, &now, true);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday += 20;
	run_test(&last_write, &now, true);
	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, true);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, true);
	now.tm_min += 2;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_minute_mod_15(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MIN;
	test_mod = 15;

	init_tm(&now, 2025, 2, 3, 4, 2, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);

	now.tm_min = 8;
	run_test(&last_write, &now, false);
	now.tm_min = 10;
	run_test(&last_write, &now, false);
	now.tm_min = 13;
	run_test(&last_write, &now, false);
	now.tm_min = 15;
	run_test(&last_write, &now, true);
	now.tm_min = 18;
	run_test(&last_write, &now, false);
	now.tm_min = 29;
	run_test(&last_write, &now, false);
	now.tm_min = 30;
	run_test(&last_write, &now, true);
	now.tm_min = 45;
	run_test(&last_write, &now, true);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);
	now.tm_hour += 1;
	now.tm_min = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	now.tm_hour += 1;
	now.tm_min += 45;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	now.tm_min += 45;
	run_test(&last_write, &now, true);
	now.tm_min += 12;
	run_test(&last_write, &now, false);

	now.tm_min++;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday += 20;
	run_test(&last_write, &now, true);
	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min = 2;
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_hour_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_HOUR;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min = 0;
	run_test(&last_write, &now, false);

	now.tm_hour++;
	run_test(&last_write, &now, true);
	now.tm_hour++;
	run_test(&last_write, &now, true);
	now.tm_min += 40;
	run_test(&last_write, &now, false);

	now.tm_hour += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_hour++;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour += 22;
	now.tm_min += 3;
	run_test(&last_write, &now, true);

	now.tm_hour = 59;
	now.tm_min = 59;
	run_test(&last_write, &now, true);
	now.tm_mday++;
	now.tm_hour = 0;
	run_test(&last_write, &now, true);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday += 20;
	run_test(&last_write, &now, true);
	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_hour_mod_12(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_HOUR;
	test_mod = 12;

	init_tm(&now, 2025, 2, 3, 4, 2, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_min = 0;
	run_test(&last_write, &now, false);

	now.tm_hour = 8;
	run_test(&last_write, &now, false);
	now.tm_hour = 10;
	run_test(&last_write, &now, false);
	now.tm_hour = 13;
	run_test(&last_write, &now, true);
	now.tm_hour = 15;
	run_test(&last_write, &now, false);
	now.tm_hour = 18;
	run_test(&last_write, &now, false);
	now.tm_hour = 23;
	run_test(&last_write, &now, false);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);
	now.tm_mday += 1;
	now.tm_hour = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	now.tm_mday += 1;
	now.tm_hour += 15;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_min++;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday += 20;
	run_test(&last_write, &now, true);
	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min = 2;
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_day_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_DAY;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min = 0;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_mday++;
	run_test(&last_write, &now, true);
	now.tm_hour += 3;
	run_test(&last_write, &now, false);

	now.tm_mday += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_mday++;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_mday += 3;
	now.tm_min += 3;
	run_test(&last_write, &now, true);

	now.tm_hour = 59;
	now.tm_min = 59;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	now.tm_hour = 0;
	run_test(&last_write, &now, true);

	now.tm_mon += 6;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_day_mod_10(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_DAY;
	test_mod = 10;

	init_tm(&now, 2025, 2, 3, 4, 2, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	now.tm_min++;
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);

	now.tm_mday = 6;
	run_test(&last_write, &now, false);
	now.tm_mday = 10;
	run_test(&last_write, &now, false);
	now.tm_mday = 11;
	run_test(&last_write, &now, true);
	now.tm_mday = 15;
	run_test(&last_write, &now, false);
	now.tm_mday = 18;
	run_test(&last_write, &now, false);
	now.tm_mday = 23;
	run_test(&last_write, &now, true);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);
	now.tm_mday += 1;
	now.tm_hour = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);
	now.tm_mon += 1;
	now.tm_mday += 1;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_hour += 12;
	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_mon++;
	run_test(&last_write, &now, true);
	now.tm_mon += 2;
	run_test(&last_write, &now, true);
	now.tm_year += 4;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min = 2;
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_month_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MONTH;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min = 0;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mday = 0;
	run_test(&last_write, &now, false);

	now.tm_mon++;
	run_test(&last_write, &now, true);
	now.tm_mon++;
	run_test(&last_write, &now, true);
	now.tm_mday += 3;
	run_test(&last_write, &now, false);

	now.tm_mon += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_mon++;
	now.tm_mday = 0;
	now.tm_hour = 0;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_mon++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_mon += 3;
	now.tm_mday += 3;
	now.tm_min += 3;
	run_test(&last_write, &now, true);

	now.tm_mday = 27;
	now.tm_hour = 59;
	now.tm_min = 59;
	run_test(&last_write, &now, false);
	now.tm_mon++;
	now.tm_hour = 0;
	run_test(&last_write, &now, true);

	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_mon++;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_month_mod_3(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MONTH;
	test_mod = 3;

	init_tm(&now, 2025, 1, 3, 4, 2, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	now.tm_min++;
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);

	now.tm_mon = 3;
	run_test(&last_write, &now, true);
	now.tm_mon = 4;
	run_test(&last_write, &now, false);
	now.tm_mon = 6;
	run_test(&last_write, &now, true);
	now.tm_mon = 8;
	run_test(&last_write, &now, false);
	now.tm_mon = 9;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);
	now.tm_mday += 1;
	now.tm_hour = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);
	now.tm_mon += 3;
	now.tm_mday += 1;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_hour += 12;
	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_year += 4;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min = 2;
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_year_mod_1(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_YEAR;
	test_mod = 1;

	init_tm(&now, 2010, 2, 3, 4, 5, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min++;
	run_test(&last_write, &now, false);
	now.tm_min = 0;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mday = 0;
	run_test(&last_write, &now, false);
	now.tm_mon++;
	run_test(&last_write, &now, false);
	now.tm_mon++;
	run_test(&last_write, &now, false);
	now.tm_mon = 0;
	run_test(&last_write, &now, false);

	now.tm_year++;
	run_test(&last_write, &now, true);
	now.tm_year++;
	run_test(&last_write, &now, true);
	now.tm_mon += 3;
	run_test(&last_write, &now, false);

	now.tm_year += 2;
	now.tm_sec = 20;
	run_test(&last_write, &now, true);

	now.tm_year++;
	now.tm_mday = 0;
	now.tm_hour = 0;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_year++;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_year += 3;
	now.tm_mday += 3;
	now.tm_min += 3;
	run_test(&last_write, &now, true);

	now.tm_mon = 3;
	now.tm_mday = 27;
	now.tm_hour = 59;
	now.tm_min = 59;
	run_test(&last_write, &now, false);
	now.tm_year++;
	now.tm_hour = 0;
	run_test(&last_write, &now, true);

	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_year++;
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_year_mod_2(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_YEAR;
	test_mod = 2;

	init_tm(&now, 2025, 1, 3, 4, 2, 6);

	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_mday++;
	run_test(&last_write, &now, false);
	now.tm_mon++;
	now.tm_mday++;
	now.tm_min++;
	now.tm_sec++;
	run_test(&last_write, &now, false);
	now.tm_hour = 0;
	run_test(&last_write, &now, false);

	now.tm_year = 2026;
	run_test(&last_write, &now, true);
	now.tm_year = 2027;
	run_test(&last_write, &now, false);
	now.tm_year = 2028;
	run_test(&last_write, &now, true);
	now.tm_year = 2029;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);
	now.tm_year = 9;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);
	now.tm_sec += 40;
	run_test(&last_write, &now, false);
	now.tm_mday += 1;
	now.tm_hour = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);
	now.tm_year += 3;
	now.tm_mday += 1;
	run_test(&last_write, &now, true);
	run_test(&last_write, &now, false);

	now.tm_hour++;
	now.tm_min = 0;
	now.tm_sec = 0;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_hour += 12;
	now.tm_min += 48;
	now.tm_sec += 3;
	run_test(&last_write, &now, false);
	run_test(&last_write, &now, false);

	now.tm_year += 4;
	run_test(&last_write, &now, true);
	now.tm_year += 6;
	run_test(&last_write, &now, true);
	now.tm_sec += 6;
	run_test(&last_write, &now, false);
	now.tm_min = 2;
	run_test(&last_write, &now, false);

	fprintf(stderr, "%s end\n", __func__);
}

static void test_check_localtime_dst_europe(void)
{
	fprintf(stderr, "%s start\n", __func__);

	struct tm now, last_write;
	memset(&last_write, 0, sizeof(last_write));
	test_intv = TIME_INTERVAL_MIN;
	test_mod = 2;

	init_tm(&now, 2025, 10, 27, 2, 56, 0);

	run_test(&last_write, &now, true);
	now.tm_min++; // 02:57.00
	run_test(&last_write, &now, false);
	now.tm_min++; // 02:58.00
	run_test(&last_write, &now, true);
	now.tm_min++; // 02:59.00
	run_test(&last_write, &now, false);
	now.tm_sec = 60; // 02:59.60
	run_test(&last_write, &now, false);

	// 02:00:00 again:
	init_tm(&now, 2025, 10, 27, 2, 0, 0);
	run_test(&last_write, &now, false);

	now.tm_min++; // 02:01.00
	run_test(&last_write, &now, false);
	now.tm_min++; // 02:02.00
	run_test(&last_write, &now, true);

	fprintf(stderr, "%s end\n", __func__);
}

int main(int argc, char **argv)
{
	/* actual tests */
	test_check_localtime_second_mod_1();
	test_check_localtime_second_mod_40();
	test_check_localtime_minute_mod_1();
	test_check_localtime_minute_mod_2();
	test_check_localtime_minute_mod_15();
	test_check_localtime_hour_mod_1();
	test_check_localtime_hour_mod_12();
	test_check_localtime_day_mod_1();
	test_check_localtime_day_mod_10();
	test_check_localtime_month_mod_1();
	test_check_localtime_month_mod_3();
	test_check_localtime_year_mod_1();
	test_check_localtime_year_mod_2();
	test_check_localtime_dst_europe();
	return 0;
}

