
/*
 * (C) 2010-2011 Alibaba Group Holding Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#include "adns_tsar.h"

#define STATS_TEST_SIZE (sizeof(struct stats_adns_utili))

static const char *adns_utili_usage = "    --adns_utili               adns_utili information";
static const char *adns_utili_command = "/home/adns/bin/adns_adm --utili";

/*
 * temp structure for collection infomation.
 */
struct stats_adns_utili {
    double    cpu0;
    double    cpu1;
    double    cpu2;
    double    cpu3;
    double    cpu4;
    double    cpu5;
    double    cpu6;
    double    cpu7;
    double    cpu8;
    double    cpu9;
};

/* Structure for adns_tsar */
static struct mod_info adns_utili_info[] = {
    {"cpu[0]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[1]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[2]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[3]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[4]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[5]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[6]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[7]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[8]", SUMMARY_BIT,  0,  STATS_NULL},
    {"cpu[9]", SUMMARY_BIT,  0,  STATS_NULL},
};

static void
read_adns_utili_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char buf[256];
    char temp[256];
    struct stats_adns_utili  st_adns_utili;

    memset(buf, 0, sizeof(buf));
    memset(&st_adns_utili, 0, sizeof(struct stats_adns_utili));

    FILE *stream;
    if ((stream = popen(adns_utili_command, "r"))) {
        fread( buf, sizeof(char), sizeof(buf), stream); 

        sscanf(buf,"%s%s%s%s%lf%s%lf%s%lf%s%lf%s%lf%s%lf%s%lf%s%lf%s%lf%s%lf",
                temp,
                temp,
                temp,
                temp,
                &st_adns_utili.cpu0,
                temp,
                &st_adns_utili.cpu1,
                temp,
                &st_adns_utili.cpu2,
                temp,
                &st_adns_utili.cpu3,
                temp,
                &st_adns_utili.cpu4,
                temp,
                &st_adns_utili.cpu5,
                temp,
                &st_adns_utili.cpu6,
                temp,
                &st_adns_utili.cpu7,
                temp,
                &st_adns_utili.cpu8,
                temp,
                &st_adns_utili.cpu9);

        pclose(stream);
    }
    int pos = sprintf(buf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu",
            /* the store order is not same as read procedure */
                (unsigned long long)(st_adns_utili.cpu0 * 10000),
                (unsigned long long)(st_adns_utili.cpu1 * 10000),
                (unsigned long long)(st_adns_utili.cpu2 * 10000),
                (unsigned long long)(st_adns_utili.cpu3 * 10000),
                (unsigned long long)(st_adns_utili.cpu4 * 10000),
                (unsigned long long)(st_adns_utili.cpu5 * 10000),
                (unsigned long long)(st_adns_utili.cpu6 * 10000),
                (unsigned long long)(st_adns_utili.cpu7 * 10000),
                (unsigned long long)(st_adns_utili.cpu8 * 10000),
                (unsigned long long)(st_adns_utili.cpu9 * 10000));
        buf[pos] = '\0';
    /* send data to adns_tsar you can get it by pre_array&cur_array at set_adns_utili_record */
    set_mod_record(mod, buf);
    return;
}

static void
set_adns_utili_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    int i;
    /* set st record */
    for (i = 0; i < 10; i++) {
        st_array[i] = ((double)cur_array[i])/10000.0;
    }
#if 0
    /* set st record */
    for (i = 0; i < mod->n_col; i++) {
	    printf("%llu\t%lf\n",cur_array[i], st_array[i]);
    }
#endif
}


/* register mod to adns_tsar */
void
mod_register(struct module *mod)
{
    register_mod_fileds(mod, "--adns_utili", adns_utili_usage, adns_utili_info, 10, read_adns_utili_stats, set_adns_utili_record);
}
