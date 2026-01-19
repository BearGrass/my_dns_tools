
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

#define STATS_TEST_SIZE (sizeof(struct stats_adns_stats))

static const char *adns_stats_usage = "    --adns_stats        get adns qps stats information";
static const char *adns_stats_command = "/home/adns/bin/adns_adm --stats";

/*
 * temp structure for collection infomation.
 */
struct stats_adns_stats {
    unsigned long long    query;
    unsigned long long    answer;
    unsigned long long    dnssec;      // DNSSEC signed answer
};

/* Structure for adns_tsar */
static struct mod_info adns_stats_info[] = {
    {" query", DETAIL_BIT,  0,  STATS_NULL},
    {"answer", DETAIL_BIT,  0,  STATS_NULL},
    {"  drop", DETAIL_BIT,  0,  STATS_NULL},
    {"dnssec", DETAIL_BIT,  0,  STATS_NULL}
};

static void
read_adns_stats_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char               buf[512];
    char temp[256];
    struct stats_adns_stats  st_adns_stats;

    memset(&st_adns_stats, 0, sizeof(struct stats_adns_stats));
    memset(buf, 0, sizeof(buf));

    FILE *stream;
    if ((stream = popen(adns_stats_command, "r"))) {
        fread( buf, sizeof(char), sizeof(buf), stream); 

        sscanf(buf,"%s%s\n"
                   "%s%s\n"
                   "%s%llu\n"
                   "%s%llu\n"
                   "%s%s\n"
                   "%s%s\n"
                   "%s%s\n"
                   "%s%s\n"
                   "%s%llu\n",
                temp, temp,
                temp, temp,
                temp, &st_adns_stats.query,
                temp, &st_adns_stats.answer,
                temp, temp,
                temp, temp,
                temp, temp,
                temp, temp,
                temp, &st_adns_stats.dnssec);

        pclose(stream);
    }
    int pos = sprintf(buf, "%llu,%llu,%llu",
            /* the store order is not same as read procedure */
            st_adns_stats.query,
            st_adns_stats.answer,
            st_adns_stats.dnssec);

    buf[pos] = '\0';
    /* send data to adns_tsar you can get it by pre_array&cur_array at set_adns_stats_record */
    set_mod_record(mod, buf);
    return;
}


static void
set_adns_stats_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    /* set st record */
    // query
    if (cur_array[0] > pre_array[0])
        st_array[0] = (double)(cur_array[0] - pre_array[0]) / (double)inter;
    else
        st_array[0] = 0;
    // answer
    if (cur_array[1] > pre_array[1])
        st_array[1] = (double)(cur_array[1] - pre_array[1]) / (double)inter;
    else
        st_array[1] = 0;
    // drop
    st_array[2] = st_array[0] - st_array[1];
    if (st_array[2] < 0) {
        st_array[2] = 0;
    }
    // dnssec answer
    if (cur_array[2] > pre_array[2])
        st_array[3] = (double)(cur_array[2] - pre_array[2]) / (double)inter;
    else
        st_array[3] = 0;

}

/* register mod to adns_tsar */
void
mod_register(struct module *mod)
{
    register_mod_fileds(mod, "--adns_stats", adns_stats_usage, adns_stats_info, 4, read_adns_stats_stats, set_adns_stats_record);
}
