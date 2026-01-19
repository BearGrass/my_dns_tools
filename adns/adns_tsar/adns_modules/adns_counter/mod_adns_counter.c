
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

#define STATS_TEST_SIZE (sizeof(struct stats_adns_counter))

static const char *adns_counter_usage = "    --adns_counter               adns_counter information";

static const char *adns_counter_command = "/home/adns/bin/adns_adm --counter";
/*
 * temp structure for collection infomation.
 */
struct stats_adns_counter {
    unsigned long long    ipv4_header_invalid;
    unsigned long long    package_error_port;
    unsigned long long    package_bad_length;
    unsigned long long    package_is_response;
    unsigned long long    parse_dns_wire_is_null_failed;
    unsigned long long    unsupport_opcode;
    unsigned long long    pars_edns_head_count_failed;
    unsigned long long    parse_edns_fomat_failed;
    unsigned long long    fill_done_process_failed;
    unsigned long long    default_view_is_not_existed;
    unsigned long long    view_exceed_max_number;
    unsigned long long    view_name_is_not_existed;
    unsigned long long    answer_with_default_failed;
    unsigned long long    answer_with_normal_failed;
    unsigned long long    gre_packet_invalid;
    unsigned long long    gre_packet_inner_ip_invalid;
    unsigned long long    gre_packet_inner_l4_invalid;
    unsigned long long    gre_packet_header_key_invalid;
};

/* Structure for adns_tsar */
static struct mod_info adns_counter_info[] = {
    {"   ihi", DETAIL_BIT,  0,  STATS_NULL},
    {"   pep", DETAIL_BIT,  0,  STATS_NULL},
    {"   pbl", DETAIL_BIT,  0,  STATS_NULL},
    {"   pir", DETAIL_BIT,  0,  STATS_NULL},
    {"pdwinf", DETAIL_BIT,  0,  STATS_NULL},
    {"    uo", DETAIL_BIT,  0,  STATS_NULL},
    {" pdhcf", DETAIL_BIT,  0,  STATS_NULL},
    {"  peff", DETAIL_BIT,  0,  STATS_NULL},
    {"  fdpf", DETAIL_BIT,  0,  STATS_NULL},
    {" dvine", DETAIL_BIT,  0,  STATS_NULL},
    {"  vemn", DETAIL_BIT,  0,  STATS_NULL},
    {" vnine", DETAIL_BIT,  0,  STATS_NULL},
    {"  awdf", DETAIL_BIT,  0,  STATS_NULL},
    {"  awnf", DETAIL_BIT,  0,  STATS_NULL},
    {"   gpi", DETAIL_BIT,  0,  STATS_NULL},
    {" gpiii", DETAIL_BIT,  0,  STATS_NULL},
    {" gpili", DETAIL_BIT,  0,  STATS_NULL},
    {" gphki", DETAIL_BIT,  0,  STATS_NULL}
};

static void
read_adns_counter_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char temp[256], buf[256];
    struct stats_adns_counter  st_adns_counter;

    memset(buf, 0, sizeof(buf));
    memset(&st_adns_counter, 0, sizeof(struct stats_adns_counter));

    FILE *stream;
    if ((stream = popen(adns_counter_command, "r"))) {
        fread( buf, sizeof(char), sizeof(buf), stream); 

        sscanf(buf,
                "%s%s%s%llu\n"
                "%s%s%s%llu\n"
                "%s%s%s%llu\n"
                "%s%s%s%llu\n"
                "%s%s%s%s%s%s%llu\n"
                "%s%s%llu\n"
                "%s%s%s%s%s%llu\n"
                "%s%s%s%s%llu\n"
                "%s%s%s%s%llu\n"
                "%s%s%s%s%s%llu\n"
                "%s%s%s%s%llu"
                "%s%s%s%s%s%llu"
                "%s%s%s%s%llu\n"
                "%s%s%s%s%llu\n"
                "%s%s%s%llu\n"
                "%s%s%s%s%s%llu\n"
                "%s%s%s%s%s%llu\n"
                "%s%s%s%s%s%llu\n",
                temp, temp, temp, &st_adns_counter.ipv4_header_invalid,
                temp, temp, temp, &st_adns_counter.package_error_port,
                temp, temp, temp, &st_adns_counter.package_bad_length,
                temp, temp, temp, &st_adns_counter.package_is_response,
                temp, temp, temp, temp, temp, temp, &st_adns_counter.parse_dns_wire_is_null_failed,
                temp, temp, &st_adns_counter.unsupport_opcode,
                temp, temp, temp, temp, temp, &st_adns_counter.pars_edns_head_count_failed,
                temp, temp, temp, temp, &st_adns_counter.parse_edns_fomat_failed,
                temp, temp, temp, temp, &st_adns_counter.fill_done_process_failed,
                temp, temp, temp, temp, temp, &st_adns_counter.default_view_is_not_existed,
                temp, temp, temp, temp, &st_adns_counter.view_exceed_max_number,
                temp, temp, temp, temp, temp, &st_adns_counter.view_name_is_not_existed,
                temp, temp, temp, temp, &st_adns_counter.answer_with_default_failed,
                temp, temp, temp, temp, &st_adns_counter.answer_with_normal_failed,
                temp, temp, temp, &st_adns_counter.gre_packet_invalid,
                temp, temp, temp, temp, temp, &st_adns_counter.gre_packet_inner_ip_invalid,
                temp, temp, temp, temp, temp, &st_adns_counter.gre_packet_inner_l4_invalid,
                temp, temp, temp, temp, temp, &st_adns_counter.gre_packet_header_key_invalid
                );

        pclose(stream);
    }
    int pos = sprintf(buf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu",
                st_adns_counter.ipv4_header_invalid,
                st_adns_counter.package_error_port,
                st_adns_counter.package_bad_length,
                st_adns_counter.package_is_response,
                st_adns_counter.parse_dns_wire_is_null_failed,
                st_adns_counter.unsupport_opcode,
                st_adns_counter.pars_edns_head_count_failed,
                st_adns_counter.parse_edns_fomat_failed,
                st_adns_counter.fill_done_process_failed,
                st_adns_counter.default_view_is_not_existed,
                st_adns_counter.view_exceed_max_number,
                st_adns_counter.view_name_is_not_existed,
                st_adns_counter.answer_with_default_failed,
                st_adns_counter.answer_with_normal_failed,
                st_adns_counter.gre_packet_invalid,
                st_adns_counter.gre_packet_inner_ip_invalid,
                st_adns_counter.gre_packet_inner_l4_invalid,
                st_adns_counter.gre_packet_header_key_invalid
                );

    buf[pos] = '\0';
    /* send data to adns_tsar you can get it by pre_array&cur_array at set_adns_counter_record */
    set_mod_record(mod, buf);
    return;
}

static void
set_adns_counter_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    int i;
    /* set st record */
    for (i = 0; i < 11; i++) {
        st_array[i] = cur_array[i];
    }
}

/* register mod to adns_tsar */
void
mod_register(struct module *mod)
{
    register_mod_fileds(mod, "--adns_counter", adns_counter_usage, adns_counter_info, 11, read_adns_counter_stats, set_adns_counter_record);
}
