
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

#define STATS_TEST_SIZE (sizeof(struct stats_adns_show))

static const char *adns_show_usage = "    --adns_show               adns_show information";
static const char *adns_show_command = "/home/adns/bin/adns_adm --show";

/*
 * temp structure for collection infomation.
 */
struct stats_adns_show {
    unsigned long long    zone_num;
    double    zone_cordon;
    unsigned long long    domain_num;
    double    domain_cordon;
    unsigned long long    record_num;
};

/* Structure for adns_tsar */
static struct mod_info adns_show_info[] = {
    {" zo_nu", DETAIL_BIT,  0,  STATS_NULL},
    {" zo_co", DETAIL_BIT,  0,  STATS_NULL},
    {" do_nu", DETAIL_BIT,  0,  STATS_NULL},
    {" do_co", DETAIL_BIT,  0,  STATS_NULL},
    {" re_nu", DETAIL_BIT,  0,  STATS_NULL},
};

static void
read_adns_show_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char buf[256];
    char temp[256];
    struct stats_adns_show  st_adns_show;

    memset(buf, 0, sizeof(buf));
    memset(&st_adns_show, 0, sizeof(struct stats_adns_show));

    FILE *stream;
    if ((stream = popen(adns_show_command, "r"))) {
        fread( buf, sizeof(char), sizeof(buf), stream); 

        sscanf(buf,
                "%s%s%s%s\n"
                "%s%llu%lf\n"
                "%s%llu%lf\n"
                "%s%llu",
                temp,
                temp,
                temp,
                temp,

                temp,
                &st_adns_show.zone_num,
                &st_adns_show.zone_cordon,
                
                temp,
                &st_adns_show.domain_num,
                &st_adns_show.domain_cordon,

                temp,
                &st_adns_show.record_num
                );

        pclose(stream);
    }
    int pos = sprintf(buf, "%llu,%llu,%llu,%llu,%llu",
            /* the store order is not same as read procedure */
                (unsigned long long)st_adns_show.zone_num,
                (unsigned long long)st_adns_show.zone_cordon * 10000,
                (unsigned long long)st_adns_show.domain_num,
                (unsigned long long)st_adns_show.domain_cordon * 10000,
                (unsigned long long)st_adns_show.record_num);

    buf[pos] = '\0';
    /* send data to adns_tsar you can get it by pre_array&cur_array at set_adns_show_record */
    set_mod_record(mod, buf);
    return;
}

static void
set_adns_show_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    int i;
    /* set st record */
    for (i = 0; i < 5; i++) {
        if (i%2) {
            st_array[i] = ((double)cur_array[i])/10000.0;
        }
        else {
            st_array[i] = cur_array[i];
        }
    }
}

/* register mod to adns_tsar */
void
mod_register(struct module *mod)
{
    register_mod_fileds(mod, "--adns_show", adns_show_usage, adns_show_info, 5, read_adns_show_stats, set_adns_show_record);
}
