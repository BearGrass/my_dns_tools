
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

#define STATS_TEST_SIZE (sizeof(struct stats_adns_rcode))

static const char *adns_rcode_usage = "    --adns_rcode               adns_rcode information";
static const char *adns_rcode_command = "/home/adns/bin/adns_adm --rcode-stats";

/*
 * temp structure for collection infomation.
 */
struct stats_adns_rcode {
    unsigned long long    noerror;
    unsigned long long    formerr;
    unsigned long long    servfail;
    unsigned long long    nxdomain;
    unsigned long long    notimpl;
    unsigned long long    refused;
    unsigned long long    notauth;
};

/* Structure for adns_tsar */
static struct mod_info adns_rcode_info[] = {
    {" noerr", SUMMARY_BIT,  0,  STATS_NULL},
    {"noerr%", SUMMARY_BIT,  0,  STATS_NULL},
    {" foerr", DETAIL_BIT,  0,  STATS_NULL},
    {"foerr%", DETAIL_BIT,  0,  STATS_NULL},
    {" serfa", DETAIL_BIT,  0,  STATS_NULL},
    {"serfa%", DETAIL_BIT,  0,  STATS_NULL},
    {" nxdom", DETAIL_BIT,  0,  STATS_NULL},
    {"nxdom%", DETAIL_BIT,  0,  STATS_NULL},
    {" noimp", DETAIL_BIT,  0,  STATS_NULL},
    {"noimp%", DETAIL_BIT,  0,  STATS_NULL},
    {" refus", DETAIL_BIT,  0,  STATS_NULL},
    {"refus%", DETAIL_BIT,  0,  STATS_NULL},
    {" noaut", DETAIL_BIT,  0,  STATS_NULL},
    {"noaut%", DETAIL_BIT,  0,  STATS_NULL},
};

static void
read_adns_rcode_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char buf[256];
    char temp[256];
    struct stats_adns_rcode  st_adns_rcode;

    memset(&st_adns_rcode, 0, sizeof(struct stats_adns_rcode));
    memset(buf, 0, sizeof(buf));

    FILE *stream;
    if ((stream = popen(adns_rcode_command, "r"))) {
        fread( buf, sizeof(char), sizeof(buf), stream); 

        sscanf(buf,"%s%llu%s%llu%s%llu%s%llu%s%llu%s%llu%s%llu",
                temp,
                &st_adns_rcode.noerror,
                temp,
                &st_adns_rcode.nxdomain,
                temp,
                &st_adns_rcode.formerr,
                temp,
                &st_adns_rcode.nxdomain,
                temp,
                &st_adns_rcode.notimpl,
                temp,
                &st_adns_rcode.refused,
                temp,
                &st_adns_rcode.notauth);

        pclose(stream);
    }
    int pos = sprintf(buf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu",
            /* the store order is not same as read procedure */
            st_adns_rcode.noerror,
            st_adns_rcode.nxdomain,
            st_adns_rcode.formerr,
            st_adns_rcode.nxdomain,
            st_adns_rcode.notimpl,
            st_adns_rcode.refused,
            st_adns_rcode.notauth);

    buf[pos] = '\0';
    /* send data to adns_tsar you can get it by pre_array&cur_array at set_adns_rcode_record */
    set_mod_record(mod, buf);
    return;
}

static void
set_adns_rcode_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    int i;
    U_64 total = 0, temp;
    /* set st record */
    for (i = 0; i < 7; i++) {
        if (cur_array[i] < pre_array[i]) {
            temp = 0;
        }
        else {
            temp = cur_array[i] - pre_array[i];
        }
        st_array[i * 2] = ((double)temp) / ((double)inter);
        total += temp;
    }
    /* set st record */
    for (i = 0; i < 7; i++) {
        if (total != 0) {
            if (cur_array[i] < pre_array[i]) {
                temp = 0;
            }
            else {
                temp = cur_array[i] - pre_array[i];
            }
            st_array[i * 2 + 1] = temp * 100.0 / (double)total;
        }
        else {
            st_array[i * 2 + 1] = 0;
        }
    }
}

/* register mod to adns_tsar */
void
mod_register(struct module *mod)
{
    register_mod_fileds(mod, "--adns_rcode", adns_rcode_usage, adns_rcode_info, 14, read_adns_rcode_stats, set_adns_rcode_record);
}
