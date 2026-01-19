#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <popt.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <limits.h>

#include "adns_utili.h"
#include "view_maps.h"
#include "libadns.h"
#include "consts.h"
#include "errcode.h"
#include "private_route.h"
#include "utili_base.h"
#include "descriptor.h"
#include "base64.h"
//#include "dnssec.h"

#define OPT_NONE                    0x000000
#define OPT_ZONE                    0x000001
#define OPT_DOMAIN                  0x000002
#define OPT_TYPE                    0x000004
#define OPT_RCLASS                  0x000008
#define OPT_TTL                     0x000010
#define OPT_RDATA                   0x000020
#define OPT_WEIGHT                  0x000040
#define OPT_VIEW                    0x000080
#define OPT_LOG_SWITCH              0x000100
#define OPT_LOG_LEVEL               0x000400
#define OPT_LOG_ROTATE_SIZE         0x000800
#define OPT_LOG_ROTATE_COUNT        0x001000
#define OPT_TYPE_PTR                0x002000
#define OPT_ZONE_QPS                0x004000
#define OPT_ZONE_BPS                0x008000
#define OPT_DOMAIN_QPS              0x010000
#define OPT_DOMAIN_BPS              0x020000
#define OPT_INTERVAL                0x040000
#define OPT_SYSLOG_SERVER_IP        0x080000
#define OPT_CNAME_CASCADE_OPT       0x100000
#define OPT_CUSTOM_VIEW_OPT         0x200000
#define OPT_WILDCARD_FALLBACK_OPT   0x400000
#define OPT_DNSSEC_OPT              0x800000
#define OPT_53                      0x1000000
#define OPT_DNSSEC_PUB              0x2000000
#define OPT_DNSSEC_PRIV             0x4000000
#define OPT_DNSSEC_ACTIVE           0x8000000
#define OPT_DNSSEC_KEY              0x10000000
#define OPT_DNSSEC_CACHE_DUMP       0x20000000
#define OPT_DNSSEC_CACHE_FLUSH      0x40000000


#define CMD_NONE                          0
#define ADNS_ADM_BATCH_MAX_NUM          20000
#define RET_MAX_LEN                       2048
#define ADNS_ADM_LINE_MAX_LEN           1024 + TXT_MAX_SIZE
/* The adns adm send buffer may contains a command entry and RDATA_MAX_SIZE's batch entries
 * which may include max BATCH_MAX_TXT_NUM TXT rrs.
 */
#define ADM_SEND_BUFF_LEN  (sizeof(struct adns_command_entry) + \
                             (sizeof(struct batch_entry) + RDATA_MAX_SIZE) * ADNS_ADM_BATCH_MAX_NUM + \
                             sizeof(struct adns_str) * BATCH_MAX_TXT_NUM)

/* Max IP segment number of a zone's private route from adns_adm side
   if the configure of private route changes at adns side, should consider modify this max number
   g_adm_send_buff is far large enough to hold 40000 IP segments */
#define ADNS_ADM_ROUTE_IPS_MAX_NUM       40000

static const char *program_name = "adns_adm";


static char *g_adm_view_map_file = "/home/adns/etc/view_name_id.map";
static char *g_adm_log_file = "/home/adns/var/log/adns_adm.log";
static struct adns_view_map g_adm_view_maps_tbl[VIEW_ID_MAX];
static int g_adm_view_num = 0;
static uint8_t g_adm_send_buff[ADM_SEND_BUFF_LEN];
static int g_adm_batch_num = 0;

/* Current batch offset in g_adm_send_buff, at the beginning of send
 * buff is adns_command_entry
 */
static int g_adm_batch_offset = sizeof(struct adns_command_entry);
static int g_fd;
char g_buf[RET_MAX_LEN];


static int adm_parse_view_map(char *file, int view_max_num, struct adns_view_map *tbl, int *view_nums);


enum {
    TAG_VMFILE = 128,
    TAG_ZONE,
    TAG_DOMAIN,

    TAG_INITLOAD,
    TAG_CLEAR,
    TAG_DUMP,
    TAG_DUMP_ALL,
    TAG_DUMP_ALLOPT,
    TAG_LOOKUP,
    TAG_QUOTA,
    TAG_ZONE_QPS,
    TAG_ZONE_BPS,
    TAG_DOMAIN_QPS,
    TAG_DOMAIN_BPS,
    TAG_INTERVAL,
    
    TAG_LOG,
    TAG_LOG_SWITCH,
    TAG_LOG_LEVEL,
    TAG_LOG_ROTATE_SIZE,
    TAG_LOG_ROTATE_COUNT,
    
    TAG_53,
    TAG_DROP53,
    TAG_RATE53,
    TAG_SIP53,
    TAG_TOTAL53,
    TAG_PPS53,
    TAG_ZONE53,
    TAG_UTILI,
    TAG_STATS,
    TAG_TCPSTATS,
    TAG_SHOW_DPDK_HEAP,
    TAG_COUNTER,
    TAG_RCODE,
    TAG_IP2VIEW,
    TAG_IPV62VIEW,
    TAG_PORT,    
    TAG_RELOAD_IPLIB,
    TAG_RELOAD_VM,
    TAG_RELOAD_NSLIST,
    TAG_SHOW_NSLIST,
    TAG_SYSLOG,
    TAG_SYSLOG_SERVER_IP,
    TAG_SYSLOG_SHOW,
    TAG_CNAME_OPT,
    TAG_WILDCARD_OPT,
    TAG_CNAME,
    TAG_WILDCARD,
    TAG_MEM_INFO,

    TAG_ADD_ROUTE,
    TAG_DEL_ROUTE,
    TAG_RELOAD_ROUTE,
    TAG_DUMP_ROUTE,
    TAG_CUSTOM_VIEW,

    TAG_DNSSEC_OPT,
    TAG_DNSSEC_PUBKEY,
    TAG_DNSSEC_PRIVKEY,
    TAG_DNSSEC_ACTIVE,
    TAG_DNSSEC_TAGS,
    TAG_DNSSEC_QUOTA,
    TAG_DNSSEC_CACHE,
    TAG_DNSSEC_CACHE_FLUSH,
    TAG_DNSSEC_CACHE_DUMP,

    TAG_QUIT,

};

static const char* optnames[] = {
    "zone",
    "domain",
    "class",
    "ttl",
    "type",
    "weight",
    "stats",
};


/*Base Function*/
static void usage_exit(const int exit_status)
{
    FILE *stream;

    if (exit_status != 0) {
        stream = stdout;
    } else {
        stream = stdout;
    }

    fprintf(stream, "Adns administrator tool\n");
    fprintf(stream, "Usage: %s <command> [options]\n", program_name);

    fprintf(stream,
            "Commands:\n"
            "  --vmfile                         specify the view map file\n"

            "  --addzone              -A        add new zone with options\n"
            "  --editzone             -E        edit zone with options\n"
            "  --delzone              -D        delete zone\n"
            "  --listzone             -L        list zone info\n"
            "  --add-rr               -a        add domain with options\n"
            "  --edit-rr              -e        edit rdata with options\n"
            "  --del-rr               -d        delete domain with options\n"
            "  --del-domain           -x        delete specified domain node\n"
            "  --del-domain-all       -O        delete specified domain node in zone for each view\n"
            "  --listdomain           -l        list domain all rr\n"
            "  --list-schedule        -u        list schedule mode for a domain or a rrset view\n"
            "  --schedule             -k        set rr-return schedule for a domain or a rrset view: all-rr, ratio or inheritance form domain(only works for rrset view), default is ratio\n"
            "  --listdomain-qps       -q        list domain qps\n"

            "  --initload                       load all data on init stage\n"
            "  --batch                -b        operate dns by batch file\n"
            "  --refresh-zone         -R        refresh zone\n"
            "  --refresh-domain       -M        refresh domain\n\n"

            "  --reload-iplib                   reload ip range view_id map files\n"
            "  --reload-vm                      reload view_name view_id map files\n"
            "  --reload-nslist                  reload default NS group list file\n"
            "  --show-nslist                    show NS group list\n"

            "  --add-route            -P        add private route for a zone\n"
            "  --del-route            -p        delete the private route for a zone\n"
            "  --reload-route         -v        reload the private route for a zone\n"
            "  --dump-route                     dump the private route for a zone\n"

            "  --add-key              -i        add a new DNSSEC key\n"
            "  --del-zsk              -g        del a ZSK\n"
            "  --add-dnskeyrrsig      -G        add RRSIG for DNSKEY, if RRSIG exists, refresh it\n"
            "  --dnssec-quota                   set DNSSEC related quota\n"
            "  --dnssec-cache                   operate DNSSEC cache\n"
            
            
            "  --dump                           dump zone and record into file\n"
            "  --lookup                         lookup zone or domain whether exsit\n"
            "  --clear                          clear all dns zone data\n"
            "  --utili                          get adns cpu/mem utilization\n"
            "  --show                 -S        get adns current the number and cordon of zone domain rr\n"
            "  --show-dpdk-heap                 get dpdk heap memory infomation\n"
            "  --status               -s        get adns server status\n"
            "  --dpdk-port                      get the dpdk port statistics\n"
            "  --rcode-stats                    get the rcode counter value\n"
            "  --stats                          get adns statistics\n"
            "  --counter                        show the counter for package dropped\n" 
            "  --ip2view                        get the view of the ip\n"
            "  --ipv62view                      get the view of the ipv6\n"
            "  --log                            look up log status, or control log switch and level\n"
            "  --quota                          lookup quota status, or control qps bps and interval\n"
            "  --syslog                         get and set syslog server IP\n"
            "  --memory-info                    show dpdk memory information\n"
            "  --set-cname-cascade    -c        enable/disable cname boost for a zone\n"
            "  --set-wildcard-fallbck -w        enable/disable wildcard fallback for a zone\n"
            "  --set-dnssec           -n        enable/disable DNSSEC for a zone\n"
            "  --quit                           quit the running ADNS\n"
            "  --help                 -h        display this help message\n\n\n"
           );

    fprintf(stream,
            "Options:\n"
            "  --zone                           zone name\n"
            "  --domain                         domain name\n"
            "  --view                 -V        view name string\n"
            "  --custom-view          -U        custom view ID\n"
            "  --rdata                -r        rr data\n"
            "  --class                -C        rr data class, default is IN\n"
            "  --type                 -t        rr data type\n"
            "  --ttl                  -T        rr data TTL\n"
            "  --weight               -w        rr data wight, only A rr has wight option, default 1\n"
            "  --mode                 -m        the shedule mode, 0:ratio, 1:all-rr, 2:inherit form domain(only works for rrset view)\n"
            "  --cname-opt                      switch for cname boost, 0 is off, other is on\n"
            "  --wildcard-opt                   switch for wildcard fallback, 0 is off, other is on\n"
            "  --switch                         <UP | DOWN> set log switch up or down default up\n"
            "  --zone-qps                       quota zone qps\n"
            "  --zone-bps                       quota zone bps\n"
            "  --domain-qps                     quota domain qps\n"
            "  --domain-bps                     quota domain bps\n"
            "  --interval                       quota interval\n"
            "  --all                            dump all zones\n"
            "  --server-ip                      specify syslog server ip\n"
            "  --show-sta                       show query statistics nodes number on every IO core\n"
            "  --dumpdb                         dump cache db\n"
            "  --level                          <ERRO | WARN | INFO | DEBUG>} set log level\n"
            "  --rotate-size                    <size + unit_char> set log rotate size:size + unit_char;size <= 1024, and unit_char is{B, K, M, G};default is 0B, means rotate disable \n"
            "  --rotate-count                   set rotate file count \n\n\n"
           );
    fprintf(stream,
            "Examples:\n"
            "  %s --vmfile view_map_file.txt\n\n"

            "  %s -A --zone myexamplezone1.org. -T 600 -r \"ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600\" [--cname-opt 1]\n"
            "  %s -E --zone myexamplezone1.org. -r \"ns1.myexamplezone1.org. mailMaster1.myexamplezone1.org. 1406084183 600 900 1209600 600\"\n"
            "  %s -D --zone myexamplezone1.org.\n"
            "  %s -L\n"
            "  %s -a --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -C IN -t A -T 600 -r \"1.1.1.1\" -w 1\n"
            "  %s -a --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -C IN -t A -T 600 -r \"1.1.1.1\" -w 1\n"            
            "  %s -e --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -C IN -t A -T 300 -r \"1.1.1.1\" -w 2\n"
            "  %s -e --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -C IN -t A -T 300 -r \"1.1.1.1\" -w 2\n"
            "  %s -d --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -C IN -t A -T 600 -r \"1.1.1.1\"\n"
            "  %s -d --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -C IN -t A -T 600 -r \"1.1.1.1\"\n"            
            "  %s -x --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT\n"
            "  %s -x --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20\n"            
            "  %s -O --zone myexamplezone1.org. --domain www1.myexamplezone1.org.\n"
            "  %s -l --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -t A\n"
            "  %s -l --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -t A\n"            
            "  %s -k --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --mode 1 -t A|AAAA(if -t omitted, A type is specified)\n"
            "  %s -k --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -t A|AAAA --mode 1\n"
            "  %s -k --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -t A|AAAA --mode 1\n"
            "  %s -u --zone myexamplezone1.org. --domain www1.myexamplezone1.org.\n"
            "  %s -u --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT -t A|AAAA\n"
            "  %s -u --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20 -t A|AAAA\n"
            "  %s -q --zone myexamplezone1.org. --domain www1.myexamplezone1.org.\n"
            
            "  %s --initload batch_file.txt\n"
            "  %s --batch batch_file.txt\n\n"
            "  %s --refresh_zone rz_batch_file.txt\n"
            "  %s --refresh_zone rd_batch_file.txt\n\n"
            "  %s --dump --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT\n"
            "  %s --dump --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20\n"            
            "  %s --lookup --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --view DEFAULT\n"
            "  %s --lookup --zone myexamplezone1.org. --domain www1.myexamplezone1.org. --custom-view 20\n"            
            "  %s --lookup --zone myexamplezone1.org.\n\n"
            "  %s --reload-iplib\n"
            "  %s --add-route --zone example.com. example_com_private_route_map_file.txt\n"
            "  %s --del-route --zone example.com.\n"
            "  %s --reload-route --zone example.com. new_private_route_map_file.txt\n"
            "  %s --dump-route --zone example.com.\n"
            "  %s --reload-vm\n"
            "  %s --reload-nslist\n"
            "  %s --clear\n"
            "  %s --utili\n"
            "  %s --stats\n"
            "  %s --counter\n"
            "  %s --ip2view 1.1.1.2\n"
            "  %s --ipv62view 2401:b180:1:1::1\n"
            "  %s --show\n"
            "  %s --show-dpdk-heap\n"
            "  %s --status\n"
            "  %s --rcode-stats\n"
            "  %s --dpdk-port\n"
            "  %s --log\n"
            "  %s --log --switch DOWN\n"
            "  %s --log --level INFO\n"
            "  %s --log --rotate-size 4G\n"
            "  %s --log --rotate-count 10\n"
            "  %s --sys53\n"
            "  %s --sys53 --drop53 0\n"
            "  %s --sys53 --rate53 1\n"
            "  %s --sys53 --sip53   5000\n"
            "  %s --sys53 --total53 50000\n"
            "  %s --pps53 --total53 450000\n"
            "  %s --quota\n"
            "  %s --quota --zone-qps 100000 --zone-bps 100000 --domain-qps 10000 --domain-bps 10000 --interval 5\n"
            "  %s --syslog\n"
            "  %s --syslog --server-ip 192.168.1.1\n"
            "  %s --syslog --show-sta\n"
            "  %s --set-cname-cascade --zone myexamplezone1.org. --cname-opt 1\n"
            "  %s --set-wildcard-fallback --zone myexamplezone1.org. --wildcard-opt 1\n"
            "  %s --set-dnssec --zone myexamplezone1.org. --dnssec-opt 1\n"
            "  %s --memory-info\n\n"

            "  %s --add-key --pub \"XXXXX\" --priv \"XXXXX\" -t ZSK|KSK \n"
            "  %s --del-zsk key_tag \n"
            "  %s --add-dnskeyrrsig --zone myexamplezone1.org. -r \"XXXXXXX\" --key \"key_tag1 key_tag2 ...\" --active keytag\n"
            "  %s --dnssec-quota --sip53    800\n"
            "  %s --dnssec-quota --total53  10000\n"
            "  %s --dnssec-quota --zone53   800\n"

            "  %s --dnssec-cache --switch <DOWN|UP>\n"
            "  %s --dnssec-cache --dumpdb\n"
            "  %s --dnssec-cache --flush\n"


            "  %s -h\n\n\n",
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name,
            program_name, program_name, program_name, program_name, program_name
           );

    fprintf(stream,
            "batch_file.txt format Examples:\n"
            "  A myexamplezone2.org. 600 ns2.myexamplezone2.org. mailMaster2.myexamplezone2.org. 1406084183 600 900 1209600 600\n" 
            "  D myexamplezone2.org.\n"
            "  a myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20 IN A 600 2.2.2.2 1\n"
            "  e myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20 IN A 300 2.2.2.2 2\n"
            "  d myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20 IN A 600 2.2.2.2\n"
            "  x myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20\n"
            "  O myexamplezone2.org. www2.myexamplezone2.org.\n"
            "  k myexamplezone2.org. www2.myexamplezone2.org. DEFAULT 1 A(if type omitted, type A is specified)\n"
            "  c myexamplezone2.org. 1\n"
            "  w myexamplezone2.org. 1\n"
            "  P myexamplezone2.org. example_com_private_route_map_file.txt\n"
            "  p myexamplezone2.org.\n"
            "  v myexamplezone2.org. new_private_route_map_file.txt\n\n"
           );

    fprintf(stream,
            "rz_batch_file.txt format (refresh zone) Examples:\n"
            "  A myexamplezone2.org. 600 ns2.myexamplezone2.org. mailMaster2.myexamplezone2.org. 1406084183 600 900 1209600 600\n"
            "  v myexamplezone2.org. new_private_route_map_file.txt\n"
            "  a myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20 IN A 600 2.2.2.2 1\n"
            "  k myexamplezone2.org. www2.myexamplezone2.org. DEFAULT 1\n"
            "  c myexamplezone2.org. 1\n"
            "  w myexamplezone2.org. 1\n"
            "  n myexamplezone2.org. 1\n\n"
           );

    fprintf(stream,
            "rd_batch_file.txt format (refresh domain) Examples:\n"
            "  a myexamplezone2.org. www2.myexamplezone2.org. DEFAULT|custom_20 IN A 600 2.2.2.2 1\n"
            "  a myexamplezone2.org. www2.myexamplezone2.org. OVERSEA|custom_20 IN A 600 3.3.3.3 1\n"
            "  k myexamplezone2.org. www2.myexamplezone2.org. DEFAULT 1\n"
           );
    exit(exit_status);
}


static void fail(int err, char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    vfprintf(stdout, msg, args);
    va_end(args);
    
    fprintf(stdout, "\n");    
    exit(err);
}


static inline const char *opt2name(int option)
{
    const char **ptr;
    for (ptr = optnames; option > 1; option >>= 1, ptr++);

    return *ptr;
}


static void
set_command(int *cmd, const int newcmd)
{
    if (*cmd != CMD_NONE)
        fail(2, "multiple commands specified");
    *cmd = newcmd;
}


static void
set_option(unsigned int *options, unsigned int option)
{
    if (*options & option)
        fail(2, "multiple '%s' options specified", opt2name(option));
    *options |= option;
}


static inline int is_digit(char *str)
{
    while (str && *str) {
        if (!isdigit(*str)) {
            return -1;
        }
        str++;
    }
    return 0;
}


static inline int strsplit(char *string, int stringlen,
        char **tokens, int maxtokens, char delim)
{
    int i, tok = 0;
    int tokstart = 1; /* first token is right at start of string */

    if (string == NULL || tokens == NULL) {
        goto einval_error;
    }

    for (i = 0; i < stringlen; i++) {
        if (string[i] == '\0' || tok >= maxtokens) {
            break;
        }
        
        if (tokstart) {
            while ((string[i] == ' ') || (string[i] == '\t')) {  
                ++i;
            }
            
            if (string[i] == '\0') {
                break; 
            }

            tokstart = 0;
            tokens[tok++] = &string[i];
        }
        
        if (string[i] == delim) {
            string[i] = '\0';
            tokstart = 1;
        }
    }    
    return tok;

einval_error:
    errno = EINVAL;
    return -1;
}


/* static functions not used in this file, comment it to avoid gcc warning
   uncomment them if used or remove static modifier */
#if 0
static char *domain_tolower(char *str)
{
    char *p = str;

    while (p && *p) {
        if (isupper(*p)) {
            *p = (char)(tolower(*p));
        }
        p++;
    }

    return str;
}
#endif

static inline int parse_caa_flags(char *str) {
    int base = 10;
    unsigned long int val;

    /*check NULL*/
    if ((str == NULL)) {
        fprintf(stdout, "CAA flags value could not be null\n");
        return -1;
    }

    /*check '.' or '-'(negative)*/
    if (is_digit(str)) {
        fprintf(stdout, "CAA flags (%s) only could be number\n", str);
        return -1;
    }

    errno = 0; /* To distinguish success/failure after call */
    val = strtoul(str, NULL, base);

    /* Check for various possible errors */
    if ((errno == ERANGE && val == ULONG_MAX) || (errno != 0 && val == 0)) {
        fprintf(stdout, "too big CAA flags value %s\n", str);
        return -1;
    }

    /* Based on the definition in RFC 6844，the CAA flags only could be 0 or 128
     * in current version. For detail, please refers to section 5.1 in RFC.
     */
    if (val != CAA_FLAGS_NONE && val != CAA_FLAGS_CRITICAL) {
        fprintf(stdout, "not supported CAA flags value %s\n", str);
        return -1;
    }

    return val;
}

static inline int parse_caa_tag(char *str) {
    char *p = str;
    int tag_len = 0;

    while (p && *p) {
        if (!isalpha(*p) && !isdigit(*p)) {
            return -1;
        }

        if (isupper(*p)) {
            *p = (char) (tolower(*p));
        }
        ++tag_len;
        ++p;

        if (tag_len > CAA_TAG_LEN_MAX) {
            fprintf(stdout,
                    "[%s]: caa tag length more than %d\n",
                    __FUNCTION__, CAA_TAG_LEN_MAX);
            return -1;
        }
    }

    if (tag_len < CAA_TAG_LEN_MIN) { /*null domain string*/
        fprintf(stdout, "[%s]: caa tag length less than %d\n",
                __FUNCTION__, CAA_TAG_LEN_MIN);
        return -1;
    }

    return tag_len;
}

static inline int parse_caa_value(char *str) {
    int len = 0;

    if (str == NULL) {
        fprintf(stdout, "[%s]: caa value is NULL\n", __FUNCTION__);
        return -1;
    }

    len = strlen(str);

    if (len > CAA_VALUE_LEN_MAX) {
        fprintf(stdout, "[%s]: caa value len large than %d\n", __FUNCTION__,
        CAA_VALUE_LEN_MAX);
        return -1;
    }

    return len;
}

static int uint16_t_check(char *str)
{
    int base = 10;
    char *endptr;    
    unsigned long long int val;
    unsigned long long int uint16_t_max = ((unsigned long long int) 1 << 16) - 1;
    unsigned int uint16_t_len_max = 5;
    
    /*check NULL, negative*/
    if ((str == NULL) || (str[0] == '-')) {
        fprintf(stdout, "not legal uint16_t %s\n", str);
        return -1; 
    }

    if (strlen(str) > uint16_t_len_max) {
        fprintf(stdout, "not legal uint16_t %s\n", str);
        return -1; 
    }
    errno = 0;    /* To distinguish success/failure after call */
    val = strtoull(str, &endptr, base);

    /* Check for various possible errors */
    if ((errno == ERANGE && (val == ULLONG_MAX))
            || (errno != 0 && val == 0)) {
        return -1;
    }

    if (endptr == str){
        fprintf(stdout, "[%s]: No digits were found\n", __FUNCTION__);
        return -1;
    }

    /* If we got here, strtol() successfully parsed a number */
    if (*endptr != '\0') {        /* Not necessarily an error... */
        fprintf(stdout, "[%s]: Further characters after number: %s\n", __FUNCTION__, endptr);
        return -1;
    }
    
    if (val > uint16_t_max) {
        return -1; 
    }
    
    return 0;
}


static int uint32_t_check(char *str)
{
    int base = 10;
    char *endptr;    
    unsigned long long int val;
    unsigned long long int uint32_t_max = ((unsigned long long int) 1 << 32) - 1;
    unsigned int uint32_t_len_max = 10;

    /*check NULL, negative*/
    if ((str == NULL) || (str[0] == '-')) {
        fprintf(stdout, "not legal uint32_t %s\n", str);
        return -1; 
    }
    if (strlen(str) > uint32_t_len_max) {
        fprintf(stdout, "not legal uint32_t %s\n", str);
        return -1; 
    }
    errno = 0;    /* To distinguish success/failure after call */
    val = strtoull(str, &endptr, base);

    /* Check for various possible errors */
    if ((errno == ERANGE && (val == ULLONG_MAX))
            || (errno != 0 && val == 0)) {
        return -1;
    }

    if (endptr == str){
        fprintf(stdout, "[%s]: No digits were found\n", __FUNCTION__);
        return -1;
    }

    /* If we got here, strtol() successfully parsed a number */
    if (*endptr != '\0') {        /* Not necessarily an error... */
        fprintf(stdout, "[%s]: Further characters after number: %s\n", __FUNCTION__, endptr);
        return -1;
    }
    
    if (val > uint32_t_max) {
        return -1; 
    }
    return 0;
}


static uint8_t *dname_str_to_wire(char *name, size_t len, int *res_len)
{
    uint8_t *wire, *label, *w;
    int wire_size;
    char *ch, *np;
      
    if (name == NULL || len == 0 || len > 255) {
        return NULL;
    }

    wire_size = len + 1;
    if (name[0] == '.' && len == 1) {
        wire_size = 1; 
        len = 0;      
    } else if (name[len - 1] != '.') {
        ++wire_size; 
    }

    *res_len = wire_size;

    wire = malloc(wire_size * sizeof(uint8_t));
    if (wire == NULL) {
        return NULL;
    }
    *wire = '\0';

    ch = name;
    np = ch + len;
    label = wire;
    w = wire + 1;
    
    while (ch != np) {
        if (*ch == '.') {
            if (*label == 0) {
                free(wire);
                return NULL;
            }
            label = w;
            *label = '\0';
        } else {
            *w = *ch;
            *label += 1;
        }
        ++w;
        ++ch;
    }

    if (*label > 0) {
        *w = '\0';
    }

    return wire;
}


static int ip_check(char *str, uint32_t af)
{
    uint8_t ip[20];

    if (((af == AF_INET) ? inet_pton(AF_INET, str, ip) : inet_pton(AF_INET6, str, ip)) != 1) {
        fprintf(stdout, "[%s]: wrong ip format %s\n", __FUNCTION__, str);
        return -1; 
    }

    return 0; 
}


static char *rm_whitespace(char *string)
{
    char *start = string + strspn(string, " \t");
    char *end = start + (strlen(start)) - 1;

    /* if only 1 char or empty, no need to trim the end */
    if(end <= start) {
        return start;
    }

    while ((*end == ' ' || *end == '\t') && end > start) {
        end--;
    }
    *(end + 1) = '\0';
    
    return start;
}

static int domain_check(char *str, uint32_t options)
{
    char *p = str;
    int domain_len = 0;
    int label_len = 0;
    
    while (p && *p) {
        if (isalpha(*p) || isdigit(*p) || *p == '-' || *p == '_' || *p == '.' ||
                /*extensive domain name*/
                ((options & OPT_DOMAIN) && !domain_len && (*p == '*') && (*(p + 1) == '.'))) {
                  
            if (isupper(*p)) {
                *p = (char)(tolower(*p));
            }

            if (*p == '.') {
                if ((domain_len > 0) && (*(p - 1) == '.')) {  /*check two dote (e.g: www..com)*/
                    fprintf(stdout, "[%s]: lable1..label2 %s\n", __FUNCTION__, str);
                    return -1; 
                }
                label_len = 0;
            } else {
                ++label_len;
            }

            ++p;
            ++domain_len;
            
            if ((label_len > LABEL_MAX_SIZE) || domain_len > DOMAIN_MAX_SIZE) {
                fprintf(stdout, "[%s]: label large than %d, or domain_len large than %d\n", __FUNCTION__, LABEL_MAX_SIZE, DOMAIN_MAX_SIZE);
                return -1; 
            }
            
            continue;
        }
        return -1;
    }

    if (domain_len == 0) {                       /*null domain string*/
        fprintf(stdout, "[%s]: null domain string\n", __FUNCTION__);
        return -1; 
    }
    
    if ((domain_len == 1) && (*str != '.')) {    /* . root domain*/
        fprintf(stdout, "[%s]: error domain %s\n", __FUNCTION__, str);
        return -1; 
    }

    return 0;
}


static int zone_is_sub_of_domain_check(char *zone, char *domain)
{
    int zone_len, domain_len;
    int T;

    if (zone == NULL || domain == NULL) {
        return -1;
    }

    zone_len = strlen(zone);
    domain_len = strlen(domain);
    if (!(zone_len && domain_len)) {
        return -1;
    }

    if (zone[zone_len - 1] != '.') {
        zone[zone_len] = '.';
        zone[++zone_len] = '\0';
    }
    
    if (domain[domain_len - 1] != '.') {
        domain[domain_len] = '.';
        domain[++domain_len] = '\0';
    }
 
    if (zone_len > domain_len) {
        return -1;
    }
 
    if ((zone_len != domain_len) && domain[domain_len - zone_len - 1] != '.') {
        return -1;
    }

    T = zone_len; 
    while(T--) {
        if (zone[--zone_len] != domain[--domain_len]) {
            return -1; 
        }
    }
    return 0;
}


static int weight_check(uint32_t weight)
{
    if (weight > WEIGHT_MAX) {
        fprintf(stdout, "[%s]: weight = %u large than %u\n", __FUNCTION__, weight, WEIGHT_MAX);
        return -1;
    }
    return 1;
}

static int key_tag_check(uint32_t key_tag)
{
    if (key_tag > KEY_TAG_MAX) {
        fprintf(stdout, "[%s]: key tag = %u large than %u\n", __FUNCTION__, key_tag, KEY_TAG_MAX);
        return -1;
    }
    return 0;
}

/*Specify Function*/
static int __parse_soa(struct batch_entry *entry, char *str)
{
    int len = 0, domain_len = 0;
    char *splits[10];
    char delim = ' ';
    char *primary, *mail;
    uint8_t *dname = NULL;

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) != 7) {
        fprintf(stdout, "[%s]: SOA format error\n", __FUNCTION__);
        return -1;
    }

    /* primary */
    if (domain_check(splits[0], OPT_DOMAIN) < 0) {
        return -1; 
    }
    primary = splits[0];
   
    dname = dname_str_to_wire(primary, strlen(primary), &domain_len);
    if (dname == NULL) {
        return -1;  
    }
    memcpy(entry->rdata, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;
    
    /* mail */
    if (domain_check(splits[1], OPT_DOMAIN) < 0) {
        return -1; 
    }
    mail = splits[1];
    dname = dname_str_to_wire(mail, strlen(mail), &domain_len);
    if (dname == NULL) {
        return -1;  
    }
    memcpy(entry->rdata + len, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;
    
    /* serial */
    if (uint32_t_check(splits[2]) < 0) {
        return -1; 
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[2]));
    len += 4;

    /* refresh */
    if (uint32_t_check(splits[3]) < 0) {
        return -1; 
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[3]));
    len += 4;

    /* retry */
    if (uint32_t_check(splits[4]) < 0) {
        return -1; 
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[4]));
    len += 4;

    /* expire */
    if (uint32_t_check(splits[5]) < 0) {
        return -1; 
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[5]));
    len += 4;

    /* minimum */
    if (uint32_t_check(splits[6]) < 0) {
        return -1; 
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[6]));
    len += 4;

    entry->rdata_len = len;

    return 0;
}


static int __parse_aname(struct batch_entry *entry, char *str)
{
    char *buf;

    if (str == NULL) {
        return -1;
    }

    buf = rm_whitespace(str);
    if (buf == NULL) {
        return -1;
    }

    if (ip_check(buf, AF_INET) < 0) {
        return -1; 
    }
    
    if (inet_pton(AF_INET, buf, entry->rdata) != 1) {
        return -1;
    }
        
    entry->rdata_len = 4;

    return 0;
}


static int __parse_aaaaname(struct batch_entry *entry, char *str)
{
    char *buf;

    if (str == NULL) {
        return -1;
    }

    buf = rm_whitespace(str);
    if (buf == NULL) {
        return -1;
    }

    if (ip_check(buf, AF_INET6) < 0) {
        return -1; 
    }
    
    if (inet_pton(AF_INET6, buf, entry->rdata) != 1) {
        return -1;
    }
    entry->rdata_len = 16;

    return 0;
}


static int __parse_domain(struct batch_entry *entry, char *str)
{
    int domain_len;
    char *domain = NULL;
    uint8_t *dname = NULL;
    
    if (entry == NULL || str == NULL) {
        return -1;
    }

    domain = rm_whitespace(str);
    if (domain_check(domain, OPT_DOMAIN) < 0) {
        return -1; 
    }
    
    dname = dname_str_to_wire(domain, strlen(domain), &domain_len);
    memcpy(entry->rdata, dname, domain_len);
    entry->rdata_len = domain_len;

    free(dname);
    return 0;
}


static int __parse_mx(struct batch_entry *entry, char *str)
{
    char *sep = " ";
    char *prefer, *domain, *pos;
    uint16_t _prefer;
    int domain_len;
    uint8_t *dname = NULL;

    str = rm_whitespace(str);
    pos = strstr(str, sep);
    if (pos == NULL) {
        return -1;
    }

    *pos = '\0';
    prefer = str;
    domain = pos + 1;
    if (domain == NULL || *domain == '\0') {
        return -1;
    }

    if (is_digit(prefer)) {
        return -1;
    }

    _prefer = (uint16_t)atoi(prefer);

    if (domain_check(domain, OPT_DOMAIN) < 0) {
        return -1; 
    }
    
    dname = dname_str_to_wire(domain, strlen(domain), &domain_len);
    _prefer = htons(_prefer);

    memcpy(entry->rdata, &_prefer, sizeof(uint16_t));
    memcpy(entry->rdata + 2, dname, domain_len);
    entry->rdata_len = domain_len + 2;

    free(dname);
    return 0;
}


static int __parse_srvname(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int i, domain_len = 0;
    uint8_t *dname = NULL;
    
    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 4) {
        return -1;
    }

    for (i = 0 ; i < 3 ; ++i) {
        if (uint16_t_check(splits[i]) < 0) {
            return -1; 
        }
        *((uint16_t *)entry->rdata + i) = htons((uint16_t)atoi(splits[i]));
    }

    if (domain_check(splits[3], OPT_DOMAIN) < 0) {
        return -1; 
    }
    
    dname = dname_str_to_wire(splits[3], strlen(splits[3]), &domain_len);
    memcpy(entry->rdata + 6, dname, domain_len);
    entry->rdata_len = domain_len + 6;

    free(dname);
    return 0;
}


/* txt format like: abcd abdsw/ asdfef
 * "/ " means " "
 */
static int parse_txt(char *rdata, uint16_t *rdata_len, char *input)
{
    int input_len;
    int input_idx;
    int cur_chstr_len = 0; // current charactor string length
    int cur_chstr_hdr_pos = 0; // the postion in the rdata to fill the header for current charactor string
    int rdata_idx = 0;
    uint8_t * __rdata = (uint8_t *)rdata;

    input = rm_whitespace(input);
    input_len = strlen(input);
    memset(__rdata, 0, sizeof(struct adns_str));

    for (input_idx = 0, rdata_idx = 1; input_idx < input_len; input_idx ++, rdata_idx++) {
        switch (input[input_idx]) {
            case '/':
                if (input[input_idx + 1] == ' ' || input[input_idx + 1] == '/') {
                    input_idx ++;
                }
                __rdata[rdata_idx] = input[input_idx];
                cur_chstr_len ++;
                break;
            case ' ':
                if (cur_chstr_len > RDATA_MAX_SIZE) {
                    return -1;
                }
                cur_chstr_hdr_pos = rdata_idx - cur_chstr_len - 1;
                __rdata[cur_chstr_hdr_pos] = cur_chstr_len;
                cur_chstr_len = 0;
                break;
            default:
                __rdata[rdata_idx] = input[input_idx];
                cur_chstr_len ++;
                break;
        }
    }
    if (cur_chstr_len > RDATA_MAX_SIZE) {
        return -1;
    }
    cur_chstr_hdr_pos = rdata_idx - cur_chstr_len - 1;
    __rdata[cur_chstr_hdr_pos] = cur_chstr_len;

    if (rdata_idx > TXT_MAX_SIZE) {
        fprintf(stdout, "[%s]: all txt len large than %d\n", __FUNCTION__, TXT_MAX_SIZE);
        return -1;
    }
    *rdata_len = rdata_idx;
    return 0;
}

/* caa format like: <flags> <tag> <value>
 */
static int __parse_caa(char *rdata, uint16_t *rdata_len, char *str) {
    /* internal function, not check parameters not null */
    int ret;
    uint8_t *pos;
    char *splits[3] = { NULL };
    char delim = ' ';

    pos = (uint8_t*)rdata;
    *rdata_len = 0;

    if (strsplit(str, strlen(str) + 1, splits, 3, delim) < 3) {
        fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
        return -1;
    }

    /* flags */
    if ((ret = parse_caa_flags(splits[0])) < 0) {
        fprintf(stdout, "[%s]: Illegal caa flags\n", __FUNCTION__);
        return -1;
    }
    pos[*rdata_len] = (uint8_t) ret;
    ++(*rdata_len);

    /* tag */
    if ((ret = parse_caa_tag(splits[1])) < 0) {
        fprintf(stdout, "[%s]: Illegal caa tag\n", __FUNCTION__);
        return -1;
    }
    pos[*rdata_len] = (uint8_t) ret;
    ++(*rdata_len);
    memcpy(pos + *rdata_len, splits[1], ret);
    (*rdata_len) += ret;

    /* value */
    str = rm_whitespace(splits[2]);
    if ((ret = parse_caa_value(str)) < 0) {
        fprintf(stdout, "[%s]: Illegal caa value\n", __FUNCTION__);
        return -1;
    }
    memcpy(pos + *rdata_len, str, ret);
    (*rdata_len) += ret;

    return 0;
}

static int parse_soa(struct adns_command_entry *ce, char *str)
{
    int len = 0, domain_len = 0;
    char *splits[10];
    char delim = ' ';
    char *primary, *mail;
    uint8_t *dname = NULL;

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) != 7) {
        fprintf(stdout, "[%s]: SOA format error\n", __FUNCTION__);
        return -1;
    }

    /* primary */
    if (domain_check(splits[0], OPT_DOMAIN) < 0) {
        return -1; 
    }
    primary = splits[0];
    
    dname = dname_str_to_wire(primary, strlen(primary), &domain_len);
    if (dname == NULL) {
        return -1;  
    }
    memcpy(ce->rdata, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;
    
    /* mail */
    if (domain_check(splits[1], OPT_DOMAIN) < 0) {
        return -1; 
    }
    mail = splits[1];
    dname = dname_str_to_wire(mail, strlen(mail), &domain_len);
    if (dname == NULL) {
        return -1;  
    }
    memcpy(ce->rdata + len, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;
    
    /* serial */
    if (uint32_t_check(splits[2]) < 0) {
        return -1; 
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[2]));
    len += 4;

    /* refresh */
    if (uint32_t_check(splits[3]) < 0) {
        return -1; 
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[3]));
    len += 4;

    /* retry */
    if (uint32_t_check(splits[4]) < 0) {
        return -1; 
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[4]));
    len += 4;

    /* expire */
    if (uint32_t_check(splits[5]) < 0) {
        return -1; 
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[5]));
    len += 4;

    /* minimum */
    if (uint32_t_check(splits[6]) < 0) {
        return -1; 
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[6]));
    len += 4;

    ce->rdata_len = len;

    return 0;
}


static int parse_aname(struct adns_command_entry *ce, char *str)
{
    char *buf;

    if (str == NULL) {
        return -1;
    }

    buf = rm_whitespace(str);
    if (buf == NULL) {
        return -1;
    }

    if (ip_check(buf, AF_INET) < 0) {
        return -1; 
    }
    
    if (inet_pton(AF_INET, buf, ce->rdata) != 1) {
        return -1;
    }
    ce->rdata_len = 4;

    return 0;
}


static int parse_aaaaname(struct adns_command_entry *ce, char *str)
{
    char *buf;

    if (str == NULL) {
        return -1;
    }

    buf = rm_whitespace(str);
    if (buf == NULL) {
        return -1;
    }

    if (ip_check(buf, AF_INET6) < 0) {
        return -1; 
    }
    
    if (inet_pton(AF_INET6, buf, ce->rdata) != 1) {
        return -1;
    }
    ce->rdata_len = 16;

    return 0;
}


static int parse_normal(struct adns_command_entry *ce, char *str)
{
    int domain_len;
    char *domain = NULL;
    uint8_t *dname = NULL;
    
    if (ce == NULL || str == NULL) {
        return -1;
    }

    domain = rm_whitespace(str);
    if (domain_check(domain, OPT_DOMAIN) < 0) {
        return -1; 
    }
    
    dname = dname_str_to_wire(domain, strlen(domain), &domain_len);
    if (dname == NULL) {
        return -1;  
    }

    memcpy(ce->rdata, dname, domain_len);
    ce->rdata_len = domain_len;

    free(dname);
    return 0;
}


static int parse_mx(struct adns_command_entry *ce, char *str)
{
    char *sep = " ";
    char *prefer, *domain, *pos;
    int domain_len;
    uint8_t *dname = NULL;

    str = rm_whitespace(str);
    pos = strstr(str, sep);
    if (pos == NULL) {
        return -1;
    }

    *pos = '\0';
    prefer = str;
    domain = pos + 1;
    if (domain == NULL || *domain == '\0') {
        return -1;
    }

    if (is_digit(prefer)) {
        return -1;
    }
    uint16_t _prefer = (uint16_t)atoi(prefer);

    if (domain_check(domain, OPT_DOMAIN) < 0) {
        return -1; 
    }
            
    dname = dname_str_to_wire(domain, strlen(domain), &domain_len);
    if (dname == NULL) {
        return -1;  
    }
    _prefer = htons(_prefer);

    memcpy(ce->rdata, &_prefer, sizeof(uint16_t));
    memcpy(ce->rdata + 2, dname, domain_len);
    ce->rdata_len = domain_len + 2;

    free(dname);
    return 0;
}

static int parse_srvname(struct adns_command_entry *ce, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int i, domain_len;
    uint8_t *dname = NULL;

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 4) {
        fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
        return -1;
    }

    for (i = 0 ; i < 3 ; ++i) {
        if (uint16_t_check(splits[i]) < 0) {
            return -1;
        }
        *((uint16_t *)ce->rdata + i) = htons((uint16_t)atoi(splits[i]));
    }

    if (domain_check(splits[3], OPT_DOMAIN) < 0) {
        return -1;
    }

    dname = dname_str_to_wire(splits[3], strlen(splits[3]), &domain_len);
    if (dname == NULL) {
        return -1;
    }

    memcpy(ce->rdata + 6, dname, domain_len);
    ce->rdata_len = domain_len + 6;

    free(dname);
    return 0;
}


static int parse_zone(struct adns_command_entry *ce, char *str)
{
    if (domain_check(str, OPT_ZONE) < 0) {
        return -1; 
    }
    
    strncpy(ce->zone, str, DOMAIN_MAX_SIZE);
    return 0;
}


static int parse_domain(struct adns_command_entry *ce, char *str)
{
    if (domain_check(str, OPT_DOMAIN) < 0) {
        return -1; 
    }
    
    strncpy(ce->domain, str, DOMAIN_MAX_SIZE);

    if (ce->cmd != CMD_DNSSEC_CACHE && zone_is_sub_of_domain_check(ce->zone, ce->domain) < 0){
        fprintf(stdout, "[%s]: zone %s is not the sub of domain %s\n", __FUNCTION__, ce->zone, ce->domain);
        return -1; 
    }
 
    return 0;
}

static int parse_key_data(char *input, uint16_t *data_len_p, char *buf)
{
    int ret;
    size_t key_len;
    char *str;
    uint16_t data_len = *data_len_p;

    str = rm_whitespace(buf);
    unsigned char key[DNS_KEY_ECDSA256SIZE];
    ret = base64_decode(key, DNS_KEY_ECDSA256SIZE, &key_len, (unsigned char*)str, strlen(str));
    if (ret < 0) {
        return -1;
    }

    //ce->rdata_len is cleared outside
    // key data is strored as key_data_len + key_data
    uint8_t *key_len_p = (uint8_t *)(input + data_len);
    *key_len_p = key_len;
    data_len += 1;

    memcpy(input + data_len, key, key_len);
    data_len += key_len;

    *data_len_p = data_len;

    return 0;
}

static int parse_type(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(type_maps); i++) {
        if (strcasecmp(type_maps[i].name, name) == 0)
            return type_maps[i].id;
    }

    return -1;
}

static int parse_rrsig_data(struct adns_command_entry *ce, char *str)
{
    int len = 0, domain_len = 0;
    char *splits[10];
    char delim = ' ';
    char *signer;
    uint8_t *dname = NULL;
    int ret;
    size_t sig_len;
    char *tmp;


    if (strsplit(str, strlen(str) + 1, splits, 10, delim) != 9) {
        fprintf(stdout, "[%s]: DNSKRY RRsig format error\n", __FUNCTION__);
        return -1;
    }

    /* type covered */
    ret = parse_type(splits[0]);
    if (ret < 0 || ret != ADNS_RRTYPE_DNSKEY) {
        fprintf(stdout, "[%s]: DNSKRY RRsig type overed error\n", __FUNCTION__);
        return -1;
    }
    *((uint16_t *)ce->rdata) = htons((uint16_t)ret);
    len += 2;

    /* algorithm */
    uint8_t algorithm = (uint8_t)atoi(splits[1]);
    if (algorithm != ECDSA_P256_ALGO) {
        fprintf(stdout, "[%s]: DNSKRY RRsig algorithm error\n", __FUNCTION__);
        return -1;
    }
    *(ce->rdata + len) = algorithm;
    len += 1;

    /* labels */
    uint8_t labels = (uint8_t)atoi(splits[2]);
    *(ce->rdata + len) = labels;
    len += 1;

    /* original ttl */
    if (uint32_t_check(splits[3]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig original TTL error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[3]));
    len += 4;

    /* sig expiration (UTC timestampt)*/
    if (uint32_t_check(splits[4]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature expiration format error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[4]));
    len += 4;

    /* sig inception (UTC timestampt)*/
    if (uint32_t_check(splits[5]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature inception format error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(ce->rdata + len) = htonl(atoi(splits[5]));
    len += 4;

    /* key tag */
    if (uint16_t_check(splits[6]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig key tag error\n", __FUNCTION__);
        return -1;
    }
    *(uint16_t *)(ce->rdata + len) = htons(atoi(splits[6]));
    len += 2;

    /* signer */
    if (domain_check(splits[7], OPT_DOMAIN) < 0) {
        return -1; 
    }
    signer = splits[7];
    dname = dname_str_to_wire(signer, strlen(signer), &domain_len);
    if (dname == NULL) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signer error\n", __FUNCTION__);
        return -1;
    }
    memcpy(ce->rdata + len, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;

    /* signature */
    tmp = rm_whitespace(splits[8]);
    unsigned char rrsig[DNS_SIG_ECDSA256SIZE];
    ret = base64_decode(rrsig, DNS_SIG_ECDSA256SIZE, &sig_len, (unsigned char*)tmp, strlen(tmp));
    if (ret < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature error\n", __FUNCTION__);
        return -1;
    }
    memcpy(ce->rdata + len, rrsig, sig_len);
    len += sig_len;
    ce->rdata_len = len;

    return 0;
}

static int parse_key_tags(struct adns_command_entry *ce, char *str)
{
    char *splits[10];
    char delim = ' ';
    uint16_t tag;
    int tag_num = 0;
    int i;

    tag_num = strsplit(str, strlen(str) + 1, splits, 10, delim);
    if ( tag_num < 1 || tag_num > MAX_ZSK_NUM) {
        fprintf(stdout, "[%s]: key tags format error\n", __FUNCTION__);
        return -1;
    }

    // save tag num in ce->ttl
    ce->ttl = (uint32_t)tag_num;

    // save tags in ce->type, ce->class
    for (i = 0; i < tag_num; i ++) {
        if (uint16_t_check(splits[i]) < 0) {
            fprintf(stdout, "[%s]: invalid key tag %s\n", __FUNCTION__, splits[i]);
            return -1;
        }
        tag = atoi(splits[i]);
        if (i == 0) {
            ce->type = tag;
        } else {
            ce->rclass = tag;
        }
    }

    return 0;
}


static int parse_rdata(struct adns_command_entry *ce, char *buf)
{
    int ret;
    int type = ce->type;

    ret = snprintf(ce->original_rdata, RDATA_MAX_SIZE, "%s", buf);
    if (ret < 0) {
        return -1;
    }

    if (ce->cmd == CMD_ADDZONE || ce->cmd == CMD_EDITZONE || ce->cmd == CMD_DELZONE || ce->cmd == CMD_LISTZONE) {
        ret = parse_soa(ce, buf);
        return ret;
    }

    if (ce->cmd == CMD_DNSSEC_ADD_DNSKEY_RRSIG) {
        ret = parse_rrsig_data(ce, buf);
        return ret;
    }

    switch (type) {
        case ADNS_RRTYPE_A:
            ret = parse_aname(ce, buf);
            break;
        case ADNS_RRTYPE_AAAA:
            ret = parse_aaaaname(ce, buf);
            break;    
        case ADNS_RRTYPE_CNAME:
        case ADNS_RRTYPE_NS:
        case ADNS_RRTYPE_PTR:
            ret = parse_normal(ce, buf);
            break;
        case ADNS_RRTYPE_MX:
            ret = parse_mx(ce, buf);
            break;
        case ADNS_RRTYPE_TXT:
            ret = parse_txt(ce->rdata, &ce->rdata_len, buf);
            break;
        case ADNS_RRTYPE_SRV:
            ret = parse_srvname(ce, buf);
            break;
        case ADNS_RRTYPE_CAA:
            ret = __parse_caa(ce->rdata, &ce->rdata_len, buf);
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}


static int parse_class(char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(class_maps); i++) {
        if (strcasecmp(class_maps[i].name, name) == 0)
            return class_maps[i].id;
    }

    return -1;
}

static int parse_key_type(const char *name)
{
    if (strcasecmp(name, DNS_ZONE_SIGNING_KEY_STR) == 0) {
        return DNS_ZONE_SIGNING_KEY_FLAGS;
    } else if (strcasecmp(name, DNS_KEY_SIGNING_KEY_STR) == 0) {
        return DNS_KEY_SIGNING_KEY_FLAGS;
    } else {
        return -1;
    }
}

static int parse_view(const char *name, uint8_t *custom_view)
{
    int i;
    char *pos = NULL, *tmp = NULL;
    if (custom_view != NULL) {
        *custom_view = 0;
    }
    pos = strstr(name, CUSTOM_VIEW_PREFIX);
    /* if view name starts with CUSTOM_VIEW_PREFIX */
    if (pos != NULL &&
        pos == name) {
        pos += strlen(CUSTOM_VIEW_PREFIX);
        tmp = pos;
        /* check custom view ID format, should only have digits after CUSTOM_VIEW_PREFIX */
        while(*pos) {
            if (*pos >= '0' && *pos <= '9') {
                pos ++;
                continue;
            }
            else {
                return -1;
            }
        }
        if (custom_view != NULL) {
            *custom_view = 1;
        }
        return atoi(tmp);
    }
    else {
        for (i = 0; i < g_adm_view_num; i++) {
            if (strcasecmp(g_adm_view_maps_tbl[i].name, name) == 0)
                return g_adm_view_maps_tbl[i].id;
        }
    }

    return -1;
}


static int parse_log_switch(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(log_switch_maps); i++) {
        if (strcasecmp(log_switch_maps[i].name, name) == 0)
            return log_switch_maps[i].id;
    }

    return -1;
}


static int parse_log_level(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(log_level_maps); i++) {
        if (strcasecmp(log_level_maps[i].name, name) == 0)
            return log_level_maps[i].id;
    }

    return -1;
}


static int check_log_rotate(const char *name)
{
    size_t len = 0;;
    char unit;
    unsigned int i = 0;
    uint64_t number;
    char num_str[ADNS_ROTATE_SIZE_MAX_LEN + 5];

    if ((name == NULL) || (name[0] == '-')) {
        return -1;
    }
    
    len = strlen(name);
    if (len > ADNS_ROTATE_SIZE_MAX_LEN) {
        return -1;
    } 
 
    for (i = 0; i < len; ++i) {
        num_str[i] = name[i];
    }
    unit = name[len - 1];

    num_str[len - 1] = '\0';
    errno = 0;
    sscanf(num_str,"%zd", &number);
    
    if (errno != 0 || number > 1024) {
        return -1;
    }
    
    if (unit == 'B') {
        return 0;
    }
    
    if (unit == 'K') {
        return 0;
    }
    
    if (unit == 'M') {
        return 0;
    }
    
    if (unit == 'G') {
        return 0;
    }
    
    return -1;
}


static int batch_parse_opcode(char *str)
{
    char op;

    if (strlen(str) < 2) {
        return -1;
    }

    op = str[0];
    switch (op) {
        case 'A':
            return CMD_ADDZONE;
        case 'D':
            return CMD_DELZONE;
        case 'E':
            return CMD_EDITZONE;
        case 'a':
            return CMD_ADDRR;
        case 'e':
            return CMD_EDITRR;
        case 'd':
            return CMD_DELRR;
        case 'x':
            return CMD_DELDOMAIN;
        case 'O':
            return CMD_DELDOMAIN_ALL;
        case 'k':
            return CMD_SCHEDULE_MODE;
        case 'c':
            return CMD_SET_CNAME_CASCADE;
        case 'w':
            return CMD_SET_WILDCARD_FALLBACK;
        case 'P':
            return CMD_ADDROUTE;
        case 'p':
            return CMD_DELROUTE;
        case 'v':
            return CMD_RELOADROUTE;
        case 'n':
            return CMD_SET_DNSSEC;
        case 'i':
            return CMD_DNSSEC_ADD_KEY;
        case 'g':
            return CMD_DNSSEC_DEL_ZSK;
        case 'G':
            return CMD_DNSSEC_ADD_DNSKEY_RRSIG;
    }

    return -1;
}


/*
 * zone| domain | view | class | type | ttl | rdata
*/
static int __parse_rr(struct batch_entry *entry, char *str)
{
    int ret;
    char *splits[10] = {NULL};
    char *ip_weight[2] = {NULL};
    char delim = ' ';
    uint32_t weight;

    if (strsplit(str, strlen(str) + 1, splits, 7, delim) < 7) {
        fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
        return -1;
    }
    
    /* zone */
    if ((ret = domain_check(splits[0], OPT_ZONE)) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

    /* domain */
    if ((ret = domain_check(splits[1], OPT_DOMAIN)) < 0) {
        fprintf(stdout, "[%s]: Illegal domain name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->domain, DOMAIN_MAX_SIZE, "%s", splits[1]);
    
    if (zone_is_sub_of_domain_check(entry->zone, entry->domain) < 0){
        fprintf(stdout, "[%s]: zone %s is not the sub of domain %s\n", __FUNCTION__, entry->zone, entry->domain);
        return -1;
    }

    /* view  */
    if((ret = parse_view(splits[2], &entry->custom_view)) < 0) {
        fprintf(stdout, "[%s]: Failed to find the view %s\n", __FUNCTION__, splits[2]);
        return -1;
    } else {
    	entry->view_id = (adns_viewid_t)ret;
    }

    /* class */
    entry->rclass = parse_class(splits[3]);
    if (entry->rclass== (uint16_t)(-1)) {
        fprintf(stdout, "[%s]: Failed to find the class %s\n", __FUNCTION__, splits[3]);
        return -1;
    }

    /* type */
    entry->type = parse_type(splits[4]);    
    if (entry->type== (uint16_t)(-1)) {
        fprintf(stdout, "[%s]: Failed to find the type %s\n", __FUNCTION__, splits[4]);
        return -1;
    }
    
    /* ttl */
    if (uint32_t_check(splits[5]) < 0) {
        fprintf(stdout, "[%s]: Illegal ttl\n", __FUNCTION__);
        return -1;
    }
    entry->ttl = atoi(splits[5]);

    /* rdata*/
    if (snprintf(entry->original_rdata, RDATA_MAX_SIZE, "%s", splits[6]) <0) {
        fprintf(stdout, "[%s]: Illegal rdata\n", __FUNCTION__);
        return -1;   
    }

    switch (entry->type) {
        case ADNS_RRTYPE_A:
        case ADNS_RRTYPE_CNAME:
            if (strsplit(splits[6], strlen(splits[6]) + 1 , ip_weight, 2, delim) < 1) {
                fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
                return -1;
            }
            
            if (ip_weight[1] != NULL) {
                if (uint32_t_check(ip_weight[1]) < 0) {
                    fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, ip_weight[1]);
                    return -1;
                }
                weight = (uint32_t)atoi(ip_weight[1]);
                if (weight_check(weight) < 0) {
                    return -1;
                }
                entry->weight = weight;
            } else {
                entry->weight = 1;
            }
            
            if (snprintf(entry->original_rdata, RDATA_MAX_SIZE, "%s", ip_weight[0]) <0) {
                fprintf(stdout, "[%s]: Illegal rdata\n", __FUNCTION__);
                return -1;   
            }
            if (entry->type == ADNS_RRTYPE_A) {
                ret = __parse_aname(entry, ip_weight[0]);
            } else if (entry->type == ADNS_RRTYPE_CNAME) {
                ret = __parse_domain(entry, ip_weight[0]);
            }
            break;
        case ADNS_RRTYPE_NS:
        case ADNS_RRTYPE_PTR:
            ret = __parse_domain(entry, splits[6]);
            break;
        case ADNS_RRTYPE_MX:
            ret = __parse_mx(entry, splits[6]);
            break;
        case ADNS_RRTYPE_AAAA:
            if (strsplit(splits[6], strlen(splits[6]) + 1 , ip_weight, 2, delim) < 1) {
                fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
                return -1;
            }
            
            if (ip_weight[1] != NULL) {
                if (uint32_t_check(ip_weight[1]) < 0) {
                    fprintf(stdout, "[%s], Formate error: %s\n", __FUNCTION__, ip_weight[1]);
                    return -1;
                }
                weight = (uint32_t)atoi(ip_weight[1]);
                if (weight_check(weight) < 0) {
                    return -1;
                }
                entry->weight = weight;
            } else {
                entry->weight = 1;
            }

            if (snprintf(entry->original_rdata, RDATA_MAX_SIZE, "%s", ip_weight[0]) <0) {
                fprintf(stdout, "[%s]: Illegal rdata\n", __FUNCTION__);
                return -1;   
            }
            ret = __parse_aaaaname(entry, ip_weight[0]);
            break;
        case ADNS_RRTYPE_TXT:
            ret = parse_txt(entry->rdata, &entry->rdata_len, splits[6]);
            break;
        case ADNS_RRTYPE_SRV:
            ret = __parse_srvname(entry, splits[6]);
            break;
        case ADNS_RRTYPE_CAA:
            ret = __parse_caa(entry->rdata, &entry->rdata_len, splits[6]);
            break;
        default:
            return -1;
    }

    return ret;
}


static int __parse_zone_to_view(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int ret;

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 3) {
        fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

    /* domain */
    if (domain_check(splits[1], OPT_DOMAIN) < 0) {
        fprintf(stdout, "[%s]: Illegal domain name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->domain, DOMAIN_MAX_SIZE, "%s", splits[1]);

    if (zone_is_sub_of_domain_check(entry->zone, entry->domain) < 0){
        fprintf(stdout, "[%s]: zone %s is not the sub of domain %s\n", __FUNCTION__, entry->zone, entry->domain);
        return -1;
    }
    
    /* view  */
    if ((ret = parse_view(splits[2], &entry->custom_view)) < 0) {
        fprintf(stdout, "[%s]: Failed to find the view: %s\n", __FUNCTION__, splits[2]);
        return -1;
    } else {
        entry->view_id = (adns_viewid_t)ret;
    }
    
    return 0;
}


static int __rr_add(struct batch_entry *entry, char *str)
{
    return __parse_rr(entry, str);
}


static int __rr_edit(struct batch_entry *entry, char *str)
{
    return __parse_rr(entry, str);
}


static int __rr_del(struct batch_entry *entry, char *str)
{
    return __parse_rr(entry, str);
}


static int __domain_del(struct batch_entry *entry, char *str)
{
    return __parse_zone_to_view(entry,  str);
}


static int __domain_del_all(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 2) {
        fprintf(stdout, "[%s]: Format error: %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);
    
    /* domain */
    if (domain_check(splits[1], OPT_DOMAIN) < 0) {
        fprintf(stdout, "[%s]: Illegal domain name\n", __FUNCTION__);
        return -1;
    } 
    snprintf(entry->domain, DOMAIN_MAX_SIZE, "%s", splits[1]);

    if (zone_is_sub_of_domain_check(entry->zone, entry->domain) < 0){
        fprintf(stdout, "[%s]: zone %s is not the sub of domain %s\n", __FUNCTION__, entry->zone, entry->domain);
        return -1;
    }
       
    return 0;
}

/* 
    k zone domain view mode [type] [set_to_line flag 0|1]
    if type omited, set schedule mode for type A
    if view|custom_view omitted, set schedule mode for domain
*/
int __set_schedule_mode(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int ret, elenum, type;

    elenum = strsplit(str, strlen(str) + 1, splits, 10, delim);
    if (elenum < 4 || elenum > 6) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }
    
    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);
    
    /* domain */
    if (domain_check(splits[1], OPT_DOMAIN) < 0) {
        fprintf(stdout, "[%s]: Illegal domain name\n", __FUNCTION__);
        return -1;
    }
    snprintf(entry->domain, DOMAIN_MAX_SIZE, "%s", splits[1]);
    if (zone_is_sub_of_domain_check(entry->zone, entry->domain) < 0){
        fprintf(stdout, "[%s]: zone %s is not the sub of domain %s\n", __FUNCTION__, entry->zone, entry->domain);
        return -1;
    }

    /* view  */
    if((ret = parse_view(splits[2], &entry->custom_view)) < 0) {
        fprintf(stdout, "[%s]: Failed to find the view %s\n", __FUNCTION__, splits[2]);
        return -1;
    } else {
    	entry->view_id = (adns_viewid_t)ret;
    }

    /* mode */
    if (uint16_t_check(splits[3]) != 0) {
        fprintf(stdout, "[%s]: Failed to convert schedule mode to a u16, %s.\n", __FUNCTION__, splits[3]);
        return -1;
    }
    entry->rclass = (uint16_t)atoi(splits[3]);

    // if type omitted, set to type A
    entry->type = ADNS_RRTYPE_A;
    // if view omitted, set schedule mode for domain
    entry->weight = 0;

    if (elenum == 6) {
        // parse type
        type = parse_type(splits[4]);
        if (type < 0) {
            fprintf(stdout, "[%s]: Invalide RR type, %s.\n", __FUNCTION__, splits[4]);
            return -1;
        }
        if (type != ADNS_RRTYPE_A && type != ADNS_RRTYPE_AAAA) {
            fprintf(stdout, "[%s]: Only A|AAAA rrset is allowed to set schedule mode, %s.\n", __FUNCTION__, splits[4]);
            return -1;
        }
        entry->type = (uint16_t)type;

        // parse set_sche_to_line flag, only 0|1 is allowed
        if (uint16_t_check(splits[5]) != 0) {
            fprintf(stdout, "[%s]: Failed to parse set_sche_to_line flag, %s.\n", __FUNCTION__, splits[5]);
            return -1;
        }
        entry->weight = (uint16_t)atoi(splits[5]);
        if (entry->weight > 1) {
            fprintf(stdout, "[%s]: Invalid set_sche_to_line flag, %s.\n", __FUNCTION__, splits[5]);
            return -1;
        }
    } else if (elenum == 5){ //elenum == 5
        type = parse_type(splits[4]);
        ret = uint16_t_check(splits[4]);
        if ((type < 0 && ret < 0) || (type >= 0 && ret >= 0)) {
            fprintf(stdout, "[%s]: %s is neither valid view nor set_sche_to_line flag\n", __FUNCTION__, splits[4]);
            return -1;
        } else if (type >= 0) {
            if (type != ADNS_RRTYPE_A && type != ADNS_RRTYPE_AAAA) {
                fprintf(stdout, "[%s]: Only A|AAAA rrset is allowed to set schedule mode, %s.\n", __FUNCTION__, splits[4]);
                return -1;
            }
            entry->type = (uint16_t)type;
        } else {
            entry->weight = (uint16_t)atoi(splits[4]);
            if (entry->weight > 1) {
                fprintf(stdout, "[%s]: Invalid set_sche_to_line flag, %s.\n", __FUNCTION__, splits[4]);
                return -1;
            }
        }
    }

    if (SCHEDULE_MODE_VALIDATE(entry->rclass, entry->weight) != 0) {
        fprintf(stdout, "[%s]: Invalid schedule mode, %u.\n", __FUNCTION__, entry->rclass);
        return -1;
    }

    return 0;
}

static int __set_cname_cascade(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 2) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }

    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

     if (uint16_t_check(splits[1]) != 0) {
        fprintf(stdout, "[%s]: Failed to convert cname options to a u16, %s.\n", __FUNCTION__, splits[1]);
        return -1;
    }
    entry->type = (uint16_t)atoi(splits[1]);
    return 0;
}

static int __set_wildcard_fallback(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 2) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }

    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

     if (uint16_t_check(splits[1]) != 0) {
        fprintf(stdout, "[%s]: Failed to convert wilcard fallback options to a u16, %s.\n", __FUNCTION__, splits[1]);
        return -1;
    }
    entry->type = (uint16_t)atoi(splits[1]);
    return 0;
}

static int __set_dnssec(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';

    if (strsplit(str, strlen(str) + 1, splits, 10, delim) < 2) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name\n", __FUNCTION__);
        return -1;
    }

    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

     if (uint16_t_check(splits[1]) != 0) {
        fprintf(stdout, "[%s]: Failed to convert dnssec options to a u16, %s.\n", __FUNCTION__, splits[1]);
        return -1;
    }
    entry->type = (uint16_t)atoi(splits[1]);
    if (entry->type > 1) {
        fprintf(stdout, "[%s]: Invalid dnssec options %s.\n", __FUNCTION__, splits[1]);
        return -1;
    }
    return 0;
}
/*
 * | key type(zsk|ksk) | pub key | priv key(optional) |
 */
static int __parse_key(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int split_num;
    int key_type;

    split_num = strsplit(str, strlen(str) + 1, splits, 10, delim);
    if (split_num < 2 || split_num > 3) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* key type ZSK|KSK */
    key_type = parse_key_type(splits[0]);
    if (key_type < 0) {
        fprintf(stdout, "[%s]: Invalid key type %s\n", __FUNCTION__, splits[0]);
        return -1;
    }
    if (key_type == DNS_KEY_SIGNING_KEY_FLAGS && split_num == 3) {
        fprintf(stdout, "[%s]: KSK not allowed to have private key %s\n", __FUNCTION__, str);
        return -1;
    }
    entry->type = key_type;

    /* pubkey */
    if (parse_key_data(entry->rdata, &(entry->rdata_len), splits[1]) < 0) {
        fprintf(stdout, "[%s]: Parse public key %s error\n", __FUNCTION__, splits[1]);
        return -1;
    }

    if (key_type == DNS_ZONE_SIGNING_KEY_FLAGS) {
        if (parse_key_data(entry->rdata, &(entry->rdata_len), splits[2]) < 0) {
            fprintf(stdout, "[%s]: Parse private key %s error\n", __FUNCTION__, splits[2]);
            return -1;
        }
    }
    
    return 0;
}

/*
 * | zone | dnskeyrrsig(type_covered algorithm labels original_ttl sig_expiration sig_inception key_tag signer signature) |
 *  active key tag | key tag1 | [key tag2] |
 */
static int __parse_dnskey_rrsig(struct batch_entry *entry, char *str)
{
    int len = 0, domain_len = 0;
    char *splits[20] = {NULL};
    char delim = ' ';
    int split_num;
    char *signer;
    uint8_t *dname = NULL;
    int ret;
    size_t sig_len;
    char *tmp;

    split_num = strsplit(str, strlen(str) + 1, splits, 20, delim);

    if ( split_num < 12 || split_num > 13) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* zone */
    if (domain_check(splits[0], OPT_ZONE) < 0) {
        fprintf(stdout, "[%s]: Illegal zone name %s\n", __FUNCTION__, splits[0]);
        return -1;
    }
    snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

    /* dnskey rrsig */
    /* type covered */
    ret = parse_type(splits[1]);
    if (ret < 0 || ret != ADNS_RRTYPE_DNSKEY) {
        fprintf(stdout, "[%s]: DNSKRY RRsig type overed error\n", __FUNCTION__);
        return -1;
    }
    *((uint16_t *)entry->rdata) = htons((uint16_t)ret);
    len += 2;

    /* algorithm */
    uint8_t algorithm = (uint8_t)atoi(splits[2]);
    if (algorithm != ECDSA_P256_ALGO) {
        fprintf(stdout, "[%s]: DNSKRY RRsig algorithm error\n", __FUNCTION__);
        return -1;
    }
    *(entry->rdata + len) = algorithm;
    len += 1;

    /* labels */
    uint8_t labels = (uint8_t)atoi(splits[3]);
    *(entry->rdata + len) = labels;
    len += 1;

    /* original ttl */
    if (uint32_t_check(splits[4]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig original TTL error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[4]));
    len += 4;

    /* sig expiration (UTC timestampt)*/
    if (uint32_t_check(splits[5]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature expiration error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[5]));
    len += 4;

    /* sig inception (UTC timestampt) */
    if (uint32_t_check(splits[6]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature inception error\n", __FUNCTION__);
        return -1;
    }
    *(uint32_t *)(entry->rdata + len) = htonl(atoi(splits[6]));
    len += 4;

    /* key tag */
    if (uint16_t_check(splits[7]) < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig key tag error\n", __FUNCTION__);
        return -1;
    }
    *(uint16_t *)(entry->rdata + len) = htons(atoi(splits[7]));
    len += 2;

    /* signer */
    if (domain_check(splits[8], OPT_DOMAIN) < 0) {
        return -1; 
    }
    signer = splits[8];
    dname = dname_str_to_wire(signer, strlen(signer), &domain_len);
    if (dname == NULL) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signer error\n", __FUNCTION__);
        return -1;
    }
    memcpy(entry->rdata + len, dname, domain_len);
    len += domain_len;
    free(dname);
    dname = NULL;

    /* signature */
    tmp = rm_whitespace(splits[9]);
    unsigned char rrsig[DNS_SIG_ECDSA256SIZE];
    ret = base64_decode(rrsig, DNS_SIG_ECDSA256SIZE, &sig_len, (unsigned char*)tmp, strlen(tmp));
    if (ret < 0) {
        fprintf(stdout, "[%s]: DNSKRY RRsig signature error\n", __FUNCTION__);
        return -1;
    }
    memcpy(entry->rdata + len, rrsig, sig_len);
    len += sig_len;
    entry->rdata_len = len;

    /* active key tag */
    if (uint16_t_check(splits[10]) < 0) {
        fprintf(stdout, "[%s]: Invalid active key tag\n", __FUNCTION__);
        return -1;
    }
    // save active key tag in weight field
    entry->weight = atoi(splits[10]);

    /* old key tag */
    if (uint16_t_check(splits[11]) < 0) {
        fprintf(stdout, "[%s]: Invalid old key tag\n", __FUNCTION__);
        return -1;
    }
    // save old key tag in type field
    entry->type = atoi(splits[11]);
    entry->ttl = 1;

    /* new key tag if any */
    if (split_num > 12) {
        if (uint16_t_check(splits[12]) < 0) {
            fprintf(stdout, "[%s]: Invalid new key tag\n", __FUNCTION__);
            return -1;
        }
        entry->ttl = 2;
        // save new key tag in rclass field
        entry->rclass = atoi(splits[12]);
    }

    return 0;
}

static int __parse_del_key_tag(struct batch_entry *entry, char *str)
{
    char *splits[10] = {NULL};
    char delim = ' ';
    int split_num;

    split_num = strsplit(str, strlen(str) + 1, splits, 10, delim);
    if (split_num != 1) {
        fprintf(stdout, "[%s]: Format error %s\n", __FUNCTION__, str);
        return -1;
    }

    /* old key tag */
    if (uint16_t_check(splits[0]) < 0) {
        fprintf(stdout, "[%s]: Invalid  key tag\n", __FUNCTION__);
        return -1;
    }
    entry->type = atoi(splits[0]);

    return 0;
}

static int __parse_private_route(struct batch_entry *entry, const char *iplib)
{
    char abs_path[PATH_MAX] = {0};

    char *abs_path_p = realpath(iplib, abs_path);
    if (abs_path_p == NULL) {
        fprintf(stderr, "[%s]: private route iplib parse: get absolute path of file: %s error\n", __FUNCTION__, iplib);
        return -1;
    }
   
    unsigned abs_len = strlen(abs_path_p);
    memcpy(entry->rdata, abs_path_p, abs_len + 1);
    entry->rdata_len = abs_len + 1;
    return 0;
}

/*
 * zone operate format
 +----------------------------+
 |      zone  opcode          |
 +-------------+--------------+
 |zone name len|   zone name  |
 +-------------+--------------+
 | rdata len   |   rdata      |
 +-------------+--------------+
 * domain operate format  
 +----------------------------------+
 |         domain opcode            |
 +----------------+-----------------+
 |     zone len   |  zone data      |
 +----------------+-----------------+
 |     domain len |  domain data    |
 +----------------+-----------------+
 |(custom)view ID |   type          |
 +----------------+-----------------+
 |     rclass     |   TTL           |
 +----------------+-----------------+
 |     weight     |                 |
 +----------------+-----------------+
 |     rdata len  |    rdata        |
 +----------------+-----------------+
 */
static int batch_put(char *line)
{
    char *str;
    /*uint8_t *entry;*/
    char *splits[10];
    char delim = ' ';
    int opcode;
    struct batch_entry *entry;
    int ret = 0;

    str = rm_whitespace(line);
    if (strlen(str) == 0) {
        return 0;
    }

    opcode = batch_parse_opcode(str);
    if (opcode < 0) {
        return -1;  
    }
    
    strsep(&str, " ");
    if (str == NULL) {
        return -1;
    }

    if (g_adm_batch_num >= ADNS_ADM_BATCH_MAX_NUM) {
        fprintf(stdout, "[%s]: g_adm_batch_num = %d larger than BATCH_MAX_NUM = %d\n",
                __FUNCTION__, g_adm_batch_num + 1, ADNS_ADM_BATCH_MAX_NUM);
        return -1;
    }
    
    /* Because the g_adm_send_buff is a static array, its value should be initialized to 0
     * by default. So need not to memset the entry structure.
     */
    entry = (struct batch_entry*)(g_adm_send_buff + g_adm_batch_offset);
    entry->opcode = opcode;
    switch (opcode) {
        /* zone */
        case CMD_ADDZONE:
        case CMD_EDITZONE:
            /*ZONE_NAME | TTL | SOA_DATA*/
            if (strsplit(str, strlen(str) + 1, splits, 3, delim) != 3) {
                return -1;
            }

            if (domain_check(splits[0], OPT_ZONE) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: Illegal zone name\n", __FUNCTION__);
            }
            snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

            if (uint32_t_check(splits[1]) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_TTL_ERROR, "[%s]: Illegal ttl value\n", __FUNCTION__);
            }
            entry->ttl = atoi(splits[1]);
            
            ret = __parse_soa(entry, splits[2]);
            if (ret != 0) {
                fail(ADNS_ADM_PARSE_BATCH_SOA_DATA_ERROR, "[%s]: Illegal soa value\n", __FUNCTION__);
            }
            break;
        case CMD_DELZONE:
            if (domain_check(str, OPT_ZONE) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: Illegal zone name\n", __FUNCTION__);
            }
            snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", str);
            break;
        
        /* rr */    
        case CMD_ADDRR:
            ret = __rr_add(entry, str);
            break;
        case CMD_EDITRR:
            ret = __rr_edit(entry, str);
            break;
        case CMD_DELRR:
            ret = __rr_del(entry, str);
            break;
        case CMD_DELDOMAIN:
            ret = __domain_del(entry, str);
            break;
        case CMD_DELDOMAIN_ALL:
            ret = __domain_del_all(entry, str);
            break;    
        case CMD_SCHEDULE_MODE:
            ret = __set_schedule_mode(entry, str);
            break;
        case CMD_SET_WILDCARD_FALLBACK:
            ret = __set_wildcard_fallback(entry, str);
            break;
        case CMD_SET_DNSSEC:
            ret = __set_dnssec(entry, str);
            break;
        case CMD_SET_CNAME_CASCADE:
            ret = __set_cname_cascade(entry, str);
            break;
        case CMD_ADDROUTE:
        case CMD_RELOADROUTE:
            /*ZONE_NAME | ROUTE_IPLIB_FILE*/
            if (strsplit(str, strlen(str) + 1, splits, 2, delim) != 2) {
                return -1;
            }
            if (domain_check(splits[0], OPT_ZONE) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: Illegal zone name\n", __FUNCTION__);
            }
            snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", splits[0]);

            ret = __parse_private_route(entry, splits[1]);
            break;
        case CMD_DELROUTE:
            if (domain_check(str, OPT_ZONE) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: Illegal zone name\n", __FUNCTION__);
            }
            snprintf(entry->zone, DOMAIN_MAX_SIZE, "%s", str);
            break;
        case CMD_DNSSEC_ADD_KEY:
            if (__parse_key(entry, str) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: parse key error\n", __FUNCTION__);
            }
            break;
        case CMD_DNSSEC_ADD_DNSKEY_RRSIG:
            if (__parse_dnskey_rrsig(entry, str) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: parse DNSKEY rrsig error\n", __FUNCTION__);
            }
            break;
        case CMD_DNSSEC_DEL_ZSK:
            if (__parse_del_key_tag(entry, str) < 0) {
                fail(ADNS_ADM_PARSE_BATCH_ZONE_ERROR, "[%s]: parse key tag error\n", __FUNCTION__);
            }
            break;
        default:
            fprintf(stdout, "[%s]: the command not exsit\n", __FUNCTION__);
            return -1;
    }
    g_adm_batch_num++;
    g_adm_batch_offset += sizeof(struct batch_entry) + entry->rdata_len;

    return ret;
}


static int parse_batch(struct adns_command_entry *ce, const char *filename)
{
    FILE *fp = NULL;
    int ret = 0, line_idx = 0;    
    char line[ADNS_ADM_LINE_MAX_LEN] = {0};

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stdout, "[%s]: Batch update: cannot open file: %s\n", __FUNCTION__, filename);
        return -1;
    }

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL) {
        line_idx++;
        if (strlen(line) > 0) {
            if (line[strlen(line) - 1] == '\n')
                line[strlen(line) - 1] = '\0';
                
            if (strlen(line) > 0 && line[strlen(line) - 1] == '\r')
                line[strlen(line) - 1] = '\0';
        }
                
        ret = batch_put(line);
        if (ret < 0) {
            fprintf(stdout, "[%s]: Failed batch parse line_num %d\n", __FUNCTION__, line_idx);
            goto err;
        }
    }
    ce->num_cmds = g_adm_batch_num;
    
    fclose(fp);
    return 0;

err:
    fclose(fp);
    return -1;
}



static int parse_options(int argc, char **argv, struct adns_command_entry *ce,
        unsigned int *options)
{
    int ret = 0, c, argint = 0;
    uint64_t arg64 = 0;
    char *argstr = NULL;
    poptContext context;

    struct poptOption options_table[] = {
        {"vmfile", '\0', POPT_ARG_STRING, &argstr, TAG_VMFILE, NULL, NULL},
        
        /* zone */
        {"addzone", 'A', POPT_ARG_NONE, NULL, 'A', NULL, NULL},
        {"delzone", 'D', POPT_ARG_NONE, NULL, 'D', NULL, NULL},
        {"editzone", 'E', POPT_ARG_NONE, NULL, 'E', NULL, NULL},
        {"listzone", 'L', POPT_ARG_NONE, NULL, 'L', NULL, NULL},
        {"refresh-zone", 'R', POPT_ARG_STRING, &argstr, 'R', NULL, NULL},
        
        /* rr*/
        {"add-rr", 'a', POPT_ARG_NONE, NULL, 'a', NULL, NULL},
        {"edit-rr", 'e', POPT_ARG_NONE, NULL, 'e', NULL, NULL},
        {"del-rr", 'd', POPT_ARG_NONE, NULL, 'd', NULL, NULL},
        {"del-domain", 'x', POPT_ARG_NONE, NULL, 'x', NULL, NULL},
        {"del-domain-all", 'O', POPT_ARG_NONE, NULL, 'O', NULL, NULL},
        {"list-domain", 'l', POPT_ARG_NONE, NULL, 'l', NULL, NULL},
        {"list-schedule", 'u', POPT_ARG_NONE, NULL, 'u', NULL, NULL},
        {"schedule", 'k', POPT_ARG_NONE, NULL, 'k', NULL, NULL},
        {"list-domain-qps", 'q', POPT_ARG_NONE, NULL, 'q', NULL, NULL},
        {"refresh-domain", 'M', POPT_ARG_STRING, &argstr, 'M', NULL, NULL},
        
        
        /* options */
        {"zone", '\0', POPT_ARG_STRING, &argstr, TAG_ZONE, NULL, NULL},
        {"domain", '\0', POPT_ARG_STRING, &argstr, TAG_DOMAIN, NULL, NULL},
        {"view", 'V', POPT_ARG_STRING, &argstr, 'V', NULL, NULL},
        {"custom-view", 'U', POPT_ARG_INT, &argint, TAG_CUSTOM_VIEW, NULL, NULL},
        {"rdata", 'r', POPT_ARG_STRING, &argstr, 'r', NULL, NULL},
        {"class", 'C', POPT_ARG_STRING, &argstr, 'C', NULL, NULL},
        {"type", 't', POPT_ARG_STRING, &argstr, 't', NULL, NULL},
        {"ttl", 'T', POPT_ARG_INT, &argint, 'T', NULL, NULL},
        {"weight", 'w', POPT_ARG_INT, &argint, 'w', NULL, NULL},
        {"mode", 'm', POPT_ARG_INT, &argint, 'm', NULL, NULL},
        {"all", '\0', POPT_ARG_NONE, &argstr, TAG_DUMP_ALL, NULL, NULL}, 
        {"allopt", '\0', POPT_ARG_NONE, &argstr, TAG_DUMP_ALLOPT, NULL, NULL}, 
        {"switch", '\0', POPT_ARG_STRING, &argstr, TAG_LOG_SWITCH, NULL, NULL},
        {"level", '\0', POPT_ARG_STRING, &argstr, TAG_LOG_LEVEL, NULL, NULL},
        {"drop53", '\0', POPT_ARG_INT, &argint, TAG_DROP53, NULL, NULL},
        {"rate53", '\0', POPT_ARG_INT, &argint, TAG_RATE53, NULL, NULL},
        {"sip53", '\0', POPT_ARG_INT, &argint, TAG_SIP53, NULL, NULL},
        {"total53", '\0', POPT_ARG_INT, &argint, TAG_TOTAL53, NULL, NULL},
        {"pps53", '\0', POPT_ARG_INT, &argint, TAG_PPS53, NULL, NULL},
        {"zone53", '\0', POPT_ARG_INT, &argint, TAG_ZONE53, NULL, NULL},
        {"rotate-size", '\0', POPT_ARG_STRING, &argstr, TAG_LOG_ROTATE_SIZE, NULL, NULL},
        {"rotate-count", '\0', POPT_ARG_STRING, &argstr, TAG_LOG_ROTATE_COUNT, NULL, NULL},
        {"server-ip", '\0', POPT_ARG_STRING, &argstr, TAG_SYSLOG_SERVER_IP, NULL, NULL},
        {"show-sta", '\0', POPT_ARG_NONE, NULL, TAG_SYSLOG_SHOW, NULL, NULL},
        {"cname-opt", '\0', POPT_ARG_INT, &argint, TAG_CNAME_OPT, NULL, NULL},
        {"wildcard-opt", '\0', POPT_ARG_INT, &argint, TAG_WILDCARD_OPT, NULL, NULL},
        {"zone-qps", '\0', POPT_ARG_INT, &argint, TAG_ZONE_QPS, NULL, NULL},
        {"zone-bps", '\0', POPT_ARG_INT, &argint, TAG_ZONE_BPS, NULL, NULL},
        {"domain-qps", '\0', POPT_ARG_INT, &argint, TAG_DOMAIN_QPS, NULL, NULL},
        {"domain-bps", '\0', POPT_ARG_INT, &argint, TAG_DOMAIN_BPS, NULL, NULL},
        {"interval", '\0', POPT_ARG_INT, &argint, TAG_INTERVAL, NULL, NULL},
        
        /* command */
        {"dump", '\0', POPT_ARG_NONE, NULL, TAG_DUMP, NULL, NULL},
        {"initload", '\0', POPT_ARG_STRING, &argstr, TAG_INITLOAD, NULL, NULL},
        {"batch", 'b', POPT_ARG_STRING, &argstr, 'b', NULL, NULL},
        {"show",  '\0', POPT_ARG_NONE, NULL, 'S', NULL, NULL},
        {"show-dpdk-heap", '\0', POPT_ARG_NONE, NULL, TAG_SHOW_DPDK_HEAP, NULL, NULL},
        {"clear", '\0', POPT_ARG_NONE, NULL, TAG_CLEAR, NULL, NULL},
        {"utili", '\0', POPT_ARG_NONE, NULL, TAG_UTILI, NULL, NULL},
        {"counter", '\0', POPT_ARG_NONE, NULL, TAG_COUNTER, NULL, NULL},
        {"dpdk-port", '\0', POPT_ARG_NONE, NULL, TAG_PORT, NULL, NULL},
        {"rcode-stats", '\0', POPT_ARG_NONE, NULL, TAG_RCODE, NULL, NULL},
        {"status", 's', POPT_ARG_NONE, NULL, 's', NULL, NULL},
        {"stats", '\0', POPT_ARG_NONE, NULL, TAG_STATS, NULL, NULL},
        {"tcpstats", '\0', POPT_ARG_NONE, NULL, TAG_TCPSTATS, NULL, NULL},
        {"reload-vm", '\0', POPT_ARG_NONE, NULL, TAG_RELOAD_VM, NULL, NULL},
        {"reload-iplib", '\0', POPT_ARG_NONE, NULL, TAG_RELOAD_IPLIB, NULL, NULL},
        {"reload-nslist", '\0', POPT_ARG_NONE, NULL, TAG_RELOAD_NSLIST, NULL, NULL},
        {"show-nslist", '\0', POPT_ARG_NONE, NULL, TAG_SHOW_NSLIST, NULL, NULL},
        {"ip2view", '\0', POPT_ARG_STRING, &argstr, TAG_IP2VIEW, NULL, NULL},
        {"ipv62view", '\0', POPT_ARG_STRING, &argstr, TAG_IPV62VIEW, NULL, NULL},
        {"lookup", '\0', POPT_ARG_NONE, NULL, TAG_LOOKUP, NULL, NULL},
        {"quota", '\0', POPT_ARG_NONE, NULL, TAG_QUOTA, NULL, NULL},
        {"log", '\0', POPT_ARG_NONE, NULL, TAG_LOG, NULL, NULL}, 
        {"sys53", '\0', POPT_ARG_NONE, NULL, TAG_53, NULL, NULL}, 
        {"syslog", '\0', POPT_ARG_NONE, NULL, TAG_SYSLOG, NULL, NULL}, 
        {"memory-info", '\0', POPT_ARG_NONE, NULL, TAG_MEM_INFO, NULL, NULL}, 
        {"set-cname-cascade", '\0', POPT_ARG_NONE, NULL, TAG_CNAME, NULL, NULL},
        {"set-wildcard-fallback", '\0', POPT_ARG_NONE, NULL, TAG_WILDCARD, NULL, NULL},


        /* private route */
        {"add-route", 'P', POPT_ARG_NONE, NULL, TAG_ADD_ROUTE, NULL, NULL},
        {"del-route", 'p', POPT_ARG_NONE, NULL, TAG_DEL_ROUTE, NULL, NULL},
        {"reload-route", 'v', POPT_ARG_NONE, NULL, TAG_RELOAD_ROUTE, NULL, NULL},
        {"dump-route", '\0', POPT_ARG_NONE, NULL, TAG_DUMP_ROUTE, NULL, NULL},

        /* DNSSEC */
        {"set-dnssec", 'n', POPT_ARG_NONE, NULL, 'n', NULL, NULL},
        {"dnssec-opt", '\0', POPT_ARG_INT, &argint, TAG_DNSSEC_OPT, NULL, NULL},
        {"add-key", 'i', POPT_ARG_NONE, NULL, 'i', NULL, NULL},
        {"pub", '\0', POPT_ARG_STRING, &argstr, TAG_DNSSEC_PUBKEY, NULL, NULL},
        {"priv", '\0', POPT_ARG_STRING, &argstr, TAG_DNSSEC_PRIVKEY, NULL, NULL},
        {"key", '\0', POPT_ARG_STRING, &argstr, TAG_DNSSEC_TAGS, NULL, NULL},
        {"active", '\0', POPT_ARG_INT, &argint, TAG_DNSSEC_ACTIVE, NULL, NULL},
        {"del-zsk", 'g', POPT_ARG_INT, &argint, 'g', NULL, NULL},
        {"add-dnskeyrrsig", 'G', POPT_ARG_NONE, NULL, 'G', NULL, NULL},
        {"dnssec-quota", '\0', POPT_ARG_NONE, NULL, TAG_DNSSEC_QUOTA, NULL, NULL},
        {"dnssec-cache", '\0', POPT_ARG_NONE, NULL, TAG_DNSSEC_CACHE, NULL, NULL},
        {"flush", '\0', POPT_ARG_NONE, NULL, TAG_DNSSEC_CACHE_FLUSH, NULL, NULL},
        {"dumpdb", '\0', POPT_ARG_NONE, NULL, TAG_DNSSEC_CACHE_DUMP, NULL, NULL},

        /* quit */
        {"quit", '\0', POPT_ARG_NONE, NULL, TAG_QUIT, NULL, NULL},
        /* help */
        {"help", 'h', POPT_ARG_NONE, NULL, 'h', NULL, NULL},
        {NULL, 0, 0, NULL, 0, NULL, NULL},
    };

    context = poptGetContext("adnstool", argc, (const char **)argv, options_table, 0);
    while (((c = poptGetNextOpt(context)) >= 0) && (ret >= 0)) {
        switch (c) {
            case TAG_VMFILE:
                ret = adm_parse_view_map(argstr, VIEW_ID_MAX, g_adm_view_maps_tbl, &g_adm_view_num);
                if (ret != 0) {
                    fail(ADNS_ADM_PARSE_VMFILE_ERROR, "[%s]: Failed to parse view map file: %s\n", __FUNCTION__, argstr);
                }
                break;
            
            /* command */    
            case 'A':
                /* Add a zone */
                set_command(&ce->cmd, CMD_ADDZONE);
                break;
            case 'D':
                /* Delete a zone */
                set_command(&ce->cmd, CMD_DELZONE);
                break;
            case 'E':
                /* Edit a zone */
                set_command(&ce->cmd, CMD_EDITZONE);
                break;
            case 'L':
                set_command(&ce->cmd, CMD_LISTZONE);
                break;                    
            case 'a':
                /* Add rr */
                set_command(&ce->cmd, CMD_ADDRR);
                break;
            case 'e':
                /* Edit rr */
                set_command(&ce->cmd, CMD_EDITRR);
                break;
            case 'd':
                /* delete rr */
                set_command(&ce->cmd, CMD_DELRR);
                break;
           case 'q':
                /* show domain qps*/
                set_command(&ce->cmd, CMD_LISTDOMAIN_QPS);
                break;
           case 'l':
                /* list a domain */
                set_command(&ce->cmd, CMD_LISTDOMAIN);
                break;
            case 'u':
                /* list the schedule mode of a domain */
                set_command(&ce->cmd, CMD_LISTSCHEDULE);
                break;
            case 'x':
                /* delete specified domain*/
                set_command(&ce->cmd, CMD_DELDOMAIN);
                break;
            case 'O':
                /* delete specified domain for each view */
                set_command(&ce->cmd, CMD_DELDOMAIN_ALL);
                break;
            case 'k':
                set_command(&ce->cmd, CMD_SCHEDULE_MODE);
                break;            
            case TAG_CLEAR:
                set_command(&ce->cmd, CMD_CLEAR);
                break;
            case TAG_DUMP:
                set_command(&ce->cmd, CMD_DUMP);
                break;
            case 'b':
                set_command(&ce->cmd, CMD_BATCH);
                ret = parse_batch(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_BATCH_ERROR, "[%s]: Failed to parse batch file on batch process...\n", __FUNCTION__);
                }
                break;        
            case 'R':
                set_command(&ce->cmd, CMD_REFRESH_ZONE);
                ret = parse_batch(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_BATCH_ERROR, "[%s]: Failed to parse batch file on batch process...\n", __FUNCTION__);
                }
                break;        
            case 'M':
                set_command(&ce->cmd, CMD_REFRESH_DOMAIN);
                ret = parse_batch(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_BATCH_ERROR, "[%s]: Failed to parse batch file on batch process...\n", __FUNCTION__);
                }
                break;

            case TAG_INITLOAD:
                set_command(&ce->cmd, CMD_INITLOAD);
                ret = parse_batch(ce, argstr);
                if (ret < 0) { 
                    fail(ADNS_ADM_PARSE_BATCH_ERROR, "[%s]: Failed parse file on initload...\n", __FUNCTION__);
                }
                break; 
            case TAG_IP2VIEW:
                set_command(&ce->cmd, CMD_IP2VIEW);
                ret = parse_aname(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_IP_ERROR, "[%s]: Failed parse ip string: e.g: adns_adm --ip2view 1.1.1.2\n", __FUNCTION__);
                }
                break;
            case TAG_IPV62VIEW:
                set_command(&ce->cmd, CMD_IPV62VIEW);
                ret = parse_aaaaname(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_IP_ERROR, "[%s]: Failed parse ipv6 string: e.g: adns_adm --ipv62view fc00:0:0:135::2\n", __FUNCTION__);
                }
                break;
            case TAG_LOOKUP:
                set_command(&ce->cmd, CMD_LOOKUP);
                break;    
            case TAG_QUOTA:
                set_command(&ce->cmd, CMD_QUOTA);
                break;    
            case TAG_UTILI:
                set_command(&ce->cmd, CMD_UTILI);
                break;
            case 's':
                set_command(&ce->cmd, CMD_STATUS);
                break;    
            case TAG_STATS:
                set_command(&ce->cmd, CMD_STATS);
                break;
            case TAG_TCPSTATS:
                set_command(&ce->cmd, CMD_TCPSTATS);
                break;
            case TAG_COUNTER:
                set_command(&ce->cmd, CMD_COUNTER);
                break;        
            case TAG_RCODE:
                set_command(&ce->cmd, CMD_RCODE_STATS);
                break;       
            case TAG_PORT:
                set_command(&ce->cmd, CMD_PORT_STATS);
                break;
            case TAG_LOG:
                set_command(&ce->cmd, CMD_LOG); 
                break; 
            case TAG_53:
                set_command(&ce->cmd, CMD_53); 
                break; 
            case TAG_RELOAD_IPLIB:
                set_command(&ce->cmd, CMD_RELOAD_IPLIB);
                break;
            case TAG_RELOAD_VM:
                set_command(&ce->cmd, CMD_RELOAD_VM);
                break;
            case TAG_RELOAD_NSLIST:
                set_command(&ce->cmd, CMD_RELOAD_NSLIST);
                break;
            case TAG_SHOW_NSLIST:
                set_command(&ce->cmd, CMD_SHOW_NSLIST);
                break;
            case 'S':
                set_command(&ce->cmd, CMD_SHOW);
                break;    
            case TAG_SHOW_DPDK_HEAP:
                set_command(&ce->cmd, CMD_SHOW_DPDK_HEAP);
                break;    
            case TAG_SYSLOG:
                set_command(&ce->cmd, CMD_SYSLOG);
                break;
            case TAG_MEM_INFO:
                set_command(&ce->cmd, CMD_MEMORY_INFO);
                break;
            case TAG_ADD_ROUTE:
                /* add private route for a zone */
                set_command(&ce->cmd, CMD_ADDROUTE);
                break;
            case TAG_DEL_ROUTE:
                /* delete private route for a zone */
                set_command(&ce->cmd, CMD_DELROUTE);
                break;
            case TAG_RELOAD_ROUTE:
                /* reload private route for a zone */
                set_command(&ce->cmd, CMD_RELOADROUTE);
                break;
            case TAG_DUMP_ROUTE:
                /* dump private route for a zone */
                set_command(&ce->cmd, CMD_DUMPROUTE);
                break;
   
            /* option*/   
            case TAG_ZONE:
                set_option(options, OPT_ZONE);                
                ret = parse_zone(ce, argstr);
                if (ret < 0) { 
                    fail(ADNS_ADM_PARSE_ZONE_ERROR, "[%s]: Illegal zone name %s\n", __FUNCTION__, argstr);
                }
                break;
            case TAG_DOMAIN:
                set_option(options, OPT_DOMAIN);
                ret = parse_domain(ce, argstr);
                if (ret < 0) { 
                    fail(ADNS_ADM_PARSE_DOMAIN_ERROR, "[%s]: Illegal domain name %s\n", __FUNCTION__, argstr);
                }
                break;
            case 'r':
                /* txt type can input multiply rr */
                if (ce->type != ADNS_RRTYPE_TXT) {
                    set_option(options, OPT_RDATA);
                } else {
                    *options |= OPT_RDATA;
                }                
                ret = parse_rdata(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_RDATA_ERROR, "[%s]: Illegal rr data %s\n", __FUNCTION__, argstr);
                }
                break;
            case 'C':
                set_option(options, OPT_RCLASS);
                ret = parse_class(argstr);
                if (ret < 0) { 
                    fail(ADNS_ADM_PARSE_CLASS_ERROR, "[%s]: Illegal rr class\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ret;
                break;
            case 't':
                set_option(options, OPT_TYPE);
                if ((*options & OPT_DNSSEC_KEY) != 0) {
                    ret = parse_key_type(argstr);
                } else {
                    ret = parse_type(argstr);
                }
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_TYPE_ERROR, "[%s]: Illegal rr type\n", __FUNCTION__);
                }
                ce->type = (uint16_t)ret;
                break;
            case 'T':
                set_option(options, OPT_TTL);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: TTL is negative\n", __FUNCTION__);
                }
                ce->ttl = (uint32_t)argint;
                break;
            case 'w':
                set_option(options, OPT_WEIGHT);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_WEIGHT_ERROR, "[%s]: Weight is negative\n", __FUNCTION__);
                }
                if (weight_check(argint) < 0) {
                    fail(ADNS_ADM_PARSE_WEIGHT_ERROR, "[%s]: Weight is illegal\n", __FUNCTION__);
                }
                ce->weight = (uint32_t)argint;
                break;
            case 'V':
                set_option(options, OPT_VIEW);
                ret = parse_view(argstr, NULL);
                if (ret < 0) { 
                    fail(ADNS_ADM_PARSE_VIEW_ERROR, "[%s]: Failed to find the view: %s\n", __FUNCTION__, argstr);
                }
                ce->view_id = (adns_viewid_t)ret;
                break;
            case 'm':
                /* schedule mode option */
                /* since the schedule mode of different rrset can be set, ce->type is used to save rrset type,
                   ce->rclass is reused to save schedule mode value */
                set_option(options, OPT_RCLASS);
                ce->rclass = (uint16_t)argint;
                break;
            case TAG_LOG_SWITCH:
                set_option(options, OPT_LOG_SWITCH);
                ce->rclass = (uint16_t)ADNS_LOG_SWITCH;
                ret = parse_log_switch(argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_LOG_SWITCH_ERROR, "[%s]: Failed to parse the switch: %s\n", __FUNCTION__, argstr);
                }
                ce->type = (uint16_t)ret;
                break;
            case TAG_LOG_LEVEL:
                set_option(options, OPT_LOG_LEVEL);
                ce->rclass = (uint16_t)ADNS_LOG_LEVEL;
                ret = parse_log_level(argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_LOG_LEVEL_ERROR, "[%s]: Failed to parse the level: %s\n", __FUNCTION__, argstr);                
                }
                ce->type = (uint16_t)ret;
                break;
            case TAG_DROP53:
                printf("%s %d\n", __FUNCTION__, __LINE__);
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: drop53 is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_DROP53;
                ce->ttl = (uint32_t)argint;
                printf("%s %d\n", __FUNCTION__, __LINE__);
                break;
            case TAG_RATE53:
                printf("%s %d\n", __FUNCTION__, __LINE__);
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: rate53(on/off) is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_RATE53;
                ce->ttl = (uint32_t)argint;
                printf("%s %d\n", __FUNCTION__, __LINE__);
                break;
            case TAG_SIP53:
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: sip 53 quota is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_SIP53;
                ce->ttl = (uint32_t)argint;
                break;
            case TAG_TOTAL53:
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: total 53 quota is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_TOTAL53;
                ce->ttl = (uint32_t)argint;
                break;
            case TAG_PPS53:
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: total pps 53 quota is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_PPS53;
                ce->ttl = (uint32_t)argint;
                break;
            case TAG_ZONE53:
                set_option(options, OPT_53);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_TTL_ERROR, "[%s]: zone 53 quota is negative\n", __FUNCTION__);
                }
                ce->rclass = (uint16_t)ADNS_ZONE53;
                ce->ttl = (uint32_t)argint;
                break;
            case TAG_LOG_ROTATE_SIZE:
                set_option(options, OPT_LOG_ROTATE_SIZE);
                ce->rclass = (uint16_t)ADNS_LOG_ROTATE_SIZE;
                ret = check_log_rotate(argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_LOG_ROTATE_SIZE_ERROR, "[%s]: Invalid option log rotate size: %s\n", __FUNCTION__, argstr);
                }
                memcpy(ce->rdata, argstr, strlen(argstr));
                break;
            case TAG_LOG_ROTATE_COUNT:
                set_option(options, OPT_LOG_ROTATE_COUNT);
                ce->rclass = (uint16_t)ADNS_LOG_ROTATE_COUNT;
                ret = uint32_t_check(argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_LOG_ROTATE_COUNT_ERROR, "[%s]: Invalid option log rotate count: %s\n", __FUNCTION__, argstr);                
                }
                memcpy(ce->rdata, argstr, strlen(argstr));
                break;
            case TAG_SYSLOG_SERVER_IP:
                set_option(options, OPT_SYSLOG_SERVER_IP);
                ce->rclass = (uint16_t)ADNS_SYSLOG_IP;
                ret = parse_aname(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADM_PARSE_LOG_ROTATE_COUNT_ERROR, "[%s]: Invalid syslog server ip: %s\n", __FUNCTION__, argstr);                
                }
                break;
            case TAG_SYSLOG_SHOW:
                // conflict with syslog server ip option
                set_option(options, OPT_SYSLOG_SERVER_IP);
                ce->rclass = (uint16_t) ADNS_SYSLOG_SHOW;
                break;
            case TAG_CNAME:
                set_command(&ce->cmd, CMD_SET_CNAME_CASCADE);
                break;
            case TAG_WILDCARD:
                set_command(&ce->cmd, CMD_SET_WILDCARD_FALLBACK);
                break;
            case 'n':
                set_command(&ce->cmd, CMD_SET_DNSSEC);
                break;
            case 'i':
                set_command(&ce->cmd, CMD_DNSSEC_ADD_KEY);
                set_option(options, OPT_DNSSEC_KEY);
                // clear rdata_len, will use rdata_len as an offset to store pub key and priv key data
                ce->rdata_len = 0;
                break;
             case 'g':
                set_command(&ce->cmd, CMD_DNSSEC_DEL_ZSK);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_KEY_TAG_ERROR, "[%s]: key tag is negative\n", __FUNCTION__);
                }
                if (key_tag_check((uint32_t)argint) < 0) {
                    fail(ADNS_ADM_PARSE_KEY_TAG_ERROR, "[%s]: key tag is illegal\n", __FUNCTION__);
                }
                // save key tag in command entry's type
                ce->type = (uint16_t)argint;
                break;
            case TAG_DNSSEC_PUBKEY:
                set_option(options, OPT_DNSSEC_PUB);
                ret = parse_key_data(ce->rdata, &(ce->rdata_len), argstr);
                if (ret < 0) {
                    fail(ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR, "[%s]: Invalid public key data: %s\n", __FUNCTION__, argstr);
                }
                break;
            case TAG_DNSSEC_PRIVKEY:
                set_option(options, OPT_DNSSEC_PRIV);
                ret = parse_key_data(ce->rdata, &(ce->rdata_len), argstr);
                if (ret < 0) {
                    fail(ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR, "[%s]: Invalid private key data: %s\n", __FUNCTION__, argstr);
                }
                break;
            case TAG_DNSSEC_TAGS:
                set_option(options, OPT_DNSSEC_KEY);
                ret = parse_key_tags(ce, argstr);
                if (ret < 0) {
                    fail(ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR, "[%s]: Invalid key tags: %s\n", __FUNCTION__, argstr);
                }
                break;
            case TAG_DNSSEC_ACTIVE:
                set_option(options, OPT_DNSSEC_ACTIVE);
                // if OPT_WEIGHT not set, ce->weight is set to 1 by default
                set_option(options, OPT_WEIGHT);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_KEY_TAG_ERROR, "[%s]: key tag is negative\n", __FUNCTION__);
                }
                if (key_tag_check((uint32_t)argint) < 0) {
                    fail(ADNS_ADM_PARSE_KEY_TAG_ERROR, "[%s]: key tag is illegal\n", __FUNCTION__);
                }
                // save active key tag is ce->weight
                ce->weight = (uint16_t)argint;
                break;
            case 'G':
                set_command(&ce->cmd, CMD_DNSSEC_ADD_DNSKEY_RRSIG);
                break;
            case TAG_DNSSEC_QUOTA:
                set_command(&ce->cmd, CMD_DNSSEC_QUOTA);
                break;
            case TAG_DNSSEC_CACHE:
                set_command(&ce->cmd, CMD_DNSSEC_CACHE);
                break;
            case TAG_DNSSEC_CACHE_FLUSH:
                set_option(options, OPT_DNSSEC_CACHE_FLUSH);
                ce->rclass = DNSSEC_CACHE_ADM_FLUSH;
                break;
            case TAG_DNSSEC_CACHE_DUMP:
                set_option(options, OPT_DNSSEC_CACHE_DUMP);
                ce->rclass = DNSSEC_CACHE_ADM_DUMP;
                break;
            case TAG_CNAME_OPT:
                set_option(options, OPT_CNAME_CASCADE_OPT);
                ce->type = (uint32_t)argint; //use type for temporary
                break;
            case TAG_WILDCARD_OPT:
                set_option(options, OPT_WILDCARD_FALLBACK_OPT);
                ce->type = (uint32_t)argint; //use type for temporary
                break;
            case TAG_DNSSEC_OPT:
                set_option(options, OPT_DNSSEC_OPT);
                ce->type = (uint32_t)argint; //use type for temporary
                break;
            case TAG_DUMP_ALL:
                set_option(options, OPT_TYPE);
                ce->type = ADNS_RRTYPE_A;
                break;
            case TAG_DUMP_ALLOPT:
                set_option(options, OPT_TYPE);
                ce->type = ADNS_RRTYPE_DS;
                break;
            case TAG_ZONE_QPS:
                set_option(options, OPT_ZONE_QPS);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_ZONE_QPS_ERROR, "[%s]: Zone QPS is negative\n", __FUNCTION__);
                }
                arg64 = argint;
                memcpy(ce->zone, &arg64, sizeof(uint64_t));
                ce->type = ADNS_RRTYPE_A;
                break;
            case TAG_ZONE_BPS:
                set_option(options, OPT_ZONE_BPS);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_ZONE_BPS_ERROR, "[%s]: Zone BPS is negative\n", __FUNCTION__);
                }
                *((uint64_t *)&(ce->zone[8])) = (uint64_t)argint;
                ce->type = ADNS_RRTYPE_A;
                break;
            case TAG_DOMAIN_QPS:
                set_option(options, OPT_DOMAIN_QPS);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_DOMAIN_QPS_ERROR, "[%s]: Domain BPS is negative\n", __FUNCTION__);
                }
                *((uint64_t *)&(ce->zone[16])) = (uint64_t)argint;
                ce->type = ADNS_RRTYPE_A;
                break;
            case TAG_DOMAIN_BPS:
                set_option(options, OPT_DOMAIN_BPS);
                if (IS_NEGATIVE(argint)) {
                    fail(ADNS_ADM_PARSE_DOMAIN_BPS_ERROR, "[%s]: Domain BPS is negative\n", __FUNCTION__);
                }
                *((uint64_t *)&(ce->zone[24])) = (uint64_t)argint;
                ce->type = ADNS_RRTYPE_A;
                break;
            case TAG_INTERVAL:
               set_option(options, OPT_INTERVAL);
               if (IS_NEGATIVE(argint)) {
                   fail(ADNS_ADM_PARSE_INTERVAL_ERROR, "[%s]: INTERVAL is negative\n", __FUNCTION__);
               }
               *((uint64_t *)&(ce->zone[32])) = (uint64_t)argint;
               ce->type = ADNS_RRTYPE_A;
               break;
            case TAG_CUSTOM_VIEW:
               set_option(options, OPT_CUSTOM_VIEW_OPT);
               if (IS_NEGATIVE(argint)) {
                   fail(ADNS_ADM_PARSE_CUSTOM_VIEW_ID_ERROR, "[%s]: custom view ID is negative\n", __FUNCTION__);
               }
               /* view ID is for private route */
               ce->custom_view = 1;
               ce->view_id = (adns_viewid_t)argint;
               break;
            case TAG_QUIT:
                set_command(&ce->cmd, CMD_QUIT);
                break;
            /* help message */
            case 'h':
                usage_exit(0);
                break;
            
            default:
                fprintf(stdout, "ERROR: Invalid option '%s'", 
                        poptBadOption(context, POPT_BADOPTION_NOALIAS));
                poptFreeContext(context);
                return -1;
        }
    }

    if (c < -1) {
        fprintf(stdout, "ERROR: %s %s\n",
                poptBadOption(context, POPT_BADOPTION_NOALIAS),
                poptStrerror(c));
        poptFreeContext(context);
        return -1;
    }

    /* extra check for CMD_SCHEDULE_MODE and CMD_LISTSCHEDULE */
    if (ce->cmd == CMD_SCHEDULE_MODE || ce->cmd == CMD_LISTSCHEDULE) {
        // not allow to set weight, since ce->weight is resued to indicate if schedule mod is set to node or line
        if ((*options & OPT_WEIGHT) != 0) {
            fprintf(stderr, "%s set/list-schedule: not allow to set weight\n", program_name);
            poptFreeContext(context);
            return -1;
        }

        // if not set --mode for CMD_SCHEDULE_MODE, command error
        if (ce->cmd == CMD_SCHEDULE_MODE && ((*options & OPT_RCLASS) == 0)) {
            fprintf(stderr, "%s set-schedule: unknown schedule mode\n", program_name);
            poptFreeContext(context);
            return -1;
        }

        // if not set --type, set type to A by default
        if ((*options & OPT_TYPE) == 0) {
            ce->type = ADNS_RRTYPE_A;
        }

        // if set --view or set --custom-view, set --type the same time, indicating setting schedule mode on a line
        if ( ((*options & OPT_VIEW) || (*options & OPT_CUSTOM_VIEW_OPT))) {
            // reuse ce->weight as a flag:
            // ce->weight == 1: set schedule mode on a line
            // ce->weight == 0: set schedule mode on a node
            ce->weight = 1;
        } else {
            ce->weight = 0;
        }

        poptFreeContext(context);
        return 0;
    }

    /* extra ADD_KEY validity check */
    if (ce->cmd == CMD_DNSSEC_ADD_KEY) {
        // pub key must be present
        if ((*options & OPT_DNSSEC_PUB) == 0) {
            fprintf(stderr, "%s add-key: must have public key\n", program_name);
            poptFreeContext(context);
            return -1;
        }
        // not allow to add private KSK
        if (ce->type == DNS_KEY_SIGNING_KEY_FLAGS && (*options & OPT_DNSSEC_PRIV) != 0) {
            fprintf(stderr, "%s add-key: not allow to add private KSK\n", program_name);
            poptFreeContext(context);
            return -1;
        }
        // ZSK must have private key
        if (ce->type == DNS_ZONE_SIGNING_KEY_FLAGS && (*options & OPT_DNSSEC_PRIV) == 0) {
            fprintf(stderr, "%s add-key: ZSK must have private key\n", program_name);
            poptFreeContext(context);
            return -1;
        }
    }

    /* extra ADD_DNSKEY_RRSIG validity check */
    if (ce->cmd == CMD_DNSSEC_ADD_DNSKEY_RRSIG) {
        // if active key tag not equal to one of the keys passed, error occurs */
        if (ce->weight != ce->type && ce->weight != ce->rclass) {
            fprintf(stderr, "%s add-dnskeyrrsig: active ZSK must be one of the keys passed\n", program_name);
            poptFreeContext(context);
            return -1;
        }
    }

    /* extra param parse for DNSSEC_CACHE command */
    if (ce->cmd == CMD_DNSSEC_CACHE) {
        // --swtich option is reused along with log command, need handle here
        if ((*options & OPT_LOG_SWITCH) != 0) {
            ce->rclass = DNSSEC_CACHE_ADM_SWITCH;
        }
    }

    /* handle add_route and reload_route command */
    if (ce->cmd == CMD_ADDROUTE ||
        ce->cmd == CMD_RELOADROUTE) {
        argstr = (char *)poptGetArg(context);
        if (argstr == NULL ||
            !(poptPeekArg(context) == NULL)) {
            fprintf(stderr, "%s add/reload_route: specify private route IP lib file\n", program_name);
            poptFreeContext(context);
            return -1;
        }
        /* get the absolute path of iplib file */
        char abs_path[PATH_MAX] = {0};
        char *abs_path_p = realpath(argstr, abs_path);
        if (abs_path_p == NULL) {
            fprintf(stderr, "%s add/reload_route: get absolute path of iplib file '%s' error\n", program_name, argstr);
            poptFreeContext(context);
            return -1;
        }
        /* for command add_route and reload_route, pass iplib file path to adns_admin, since the size of command content buffer
           is limited, it is up to adns to parse and load the iplib file */
        unsigned path_len = strlen(abs_path_p);
        /* copy the iplib path to command entry's rdata field, including the end '\0' */
        memcpy(ce->rdata, abs_path_p, path_len + 1);
        ce->rdata_len = path_len + 1;
        /* update the offset */
        g_adm_batch_offset += (path_len + 1);
    }

    /* if weight value is not specified by adns_adm command option, set to default value 1 */
    if ((*options & OPT_WEIGHT) == 0) {
        ce->weight = 1;
    }

    poptFreeContext(context);
    return ret;
}


static int options_check(uint32_t options, int cmd)
{
    int ret = 0;

    switch (cmd) {
        case CMD_ADDZONE:
        case CMD_EDITZONE:
            if (((options & OPT_ZONE) == 0) || ((options & OPT_RDATA) == 0)) {
                ret = -1;
            }
            //not force to check OPT_ZONE_CNAME_CASCADE
            break;
            
        case CMD_DELZONE:
        case CMD_ADDROUTE:
        case CMD_DELROUTE:
        case CMD_RELOADROUTE:
        case CMD_DUMPROUTE:
            if ((options & OPT_ZONE) == 0) {
                ret = -1;
            }
            break;
        case CMD_LISTZONE:   
            break;
            
        case CMD_ADDRR:
        case CMD_EDITRR:
        case CMD_DELRR:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if (((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0) || ((options & OPT_RDATA) == 0)) {
                ret = -1;
            }
            break;
            
        case CMD_DELDOMAIN:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if (((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0) || ( ((options & OPT_VIEW) == 0) && !(options & OPT_CUSTOM_VIEW_OPT) )) {
                ret = -1;
            }
            break;
            
        case CMD_DELDOMAIN_ALL:
            if (((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0)) {
                ret = -1;
            }
            break;
 
        case CMD_DUMP:
            if ((options & OPT_TYPE) != 0) {
                break; 
            }
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if (!(options & OPT_ZONE)) {
                ret = -1;
            }
            if ( !(options & OPT_DOMAIN) && ((options & OPT_VIEW) || (options & OPT_CUSTOM_VIEW_OPT)) ) {
                ret = -3;
            }
            break;
            
        case CMD_LOOKUP:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            /*lookup domain*/
            if (((options & OPT_ZONE) != 0) && ((options & OPT_DOMAIN) != 0) && ( ((options & OPT_VIEW) != 0) || (options & OPT_CUSTOM_VIEW_OPT)) ) {
                break;
            }
            /*lookup zone*/
            if ((options & OPT_ZONE) != 0) {
                break; 
            }
            ret = -1;
        case CMD_QUOTA:
            if (((options & OPT_ZONE_BPS) != 0) && ((options & OPT_ZONE_QPS) != 0) && ((options & OPT_DOMAIN_BPS) != 0) && ((options & OPT_DOMAIN_QPS) != 0) && ((options & OPT_INTERVAL) != 0)) {
                break;
            }

            if (((options & OPT_ZONE_BPS) == 0) && ((options & OPT_ZONE_QPS) == 0) && ((options & OPT_INTERVAL) == 0) && ((options & OPT_DOMAIN_QPS) == 0) && ((options & OPT_INTERVAL) == 0)) {
                break;
            }
            ret = -1;
    
        case CMD_LISTDOMAIN:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if (((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0) || 
                   ( ((options & OPT_VIEW) == 0) && !(options & OPT_CUSTOM_VIEW_OPT) ) || ((options & OPT_TYPE) == 0)) {
                ret = -1;
            }
            break;

        case CMD_LISTSCHEDULE:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_SCHEDULE_MODE:
            if ( (options & OPT_VIEW) && (options & OPT_CUSTOM_VIEW_OPT) ) {
                ret = -2;
            }
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_DOMAIN) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_SET_CNAME_CASCADE:
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_CNAME_CASCADE_OPT) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_SET_WILDCARD_FALLBACK:
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_WILDCARD_FALLBACK_OPT) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_SET_DNSSEC:
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_DNSSEC_OPT) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_DNSSEC_ADD_KEY:
            if ( ((options & OPT_TYPE) == 0) || ((options & OPT_DNSSEC_KEY) == 0) ||
                 ((options & OPT_DNSSEC_PUB) == 0) ) {
                ret = -1;
            }
            break;

        case CMD_DNSSEC_ADD_DNSKEY_RRSIG:
            if ( ((options & OPT_ZONE) == 0) || ((options & OPT_RDATA) == 0) || 
                ((options & OPT_DNSSEC_KEY) == 0) || ((options & OPT_DNSSEC_ACTIVE) == 0) ) {
                ret = -1;
            }
            break;

        default:
            break;
    }
        
    if (ret == -1) {
        fprintf(stderr, "[%s]: options not enough\n", __FUNCTION__);
    }
    if (ret == -2) {
        fprintf(stderr, "[%s]: not allow to specify 'view' and 'custom-view' at the same time\n", __FUNCTION__);
    }

    return ret;
}


static int process_options(int argc, char **argv)
{
    struct adns_command_entry *ce;
    unsigned int options = OPT_NONE;
    int ret;

    /* At the beginning of send buffer is the adns_command_entry, because the
     * g_adm_send_buff is a static array, its value should be initialized to 0
     * by default.
     */
    ce = (struct adns_command_entry*)g_adm_send_buff;

    if (parse_options(argc, argv, ce, &options) < 0) {
        return -1;
    }

    if (options_check(options, ce->cmd) < 0) {
        return -1;
    }

    ret = socket_init();
    if (ret != ADNS_ADM_OK) {
        exit(ret); 
    }

    switch (ce->cmd) {
        /* zone */
        case CMD_ADDZONE:
            ret = adns_add_zone(ce);
            break;
        case CMD_DELZONE:
            ret = adns_del_zone(ce);
            break;
        case CMD_EDITZONE:
            ret = adns_edit_zone(ce);
            break;
        case CMD_LISTZONE:
            ret = adns_list_zone(ce);
            break;
            
        /* rr */        
        case CMD_ADDRR:
            ret = adns_add_rr(ce);
            break;
        case CMD_EDITRR:
            ret = adns_edit_rr(ce);
            break;
        case CMD_DELRR:
            ret = adns_del_rr(ce);
            break;       
        case CMD_DELDOMAIN:
            ret = adns_del_domain(ce);
            break;
        case CMD_DELDOMAIN_ALL:
           ret = adns_del_domain(ce);
           break;
        case CMD_LISTDOMAIN:
            ret = adns_list_dname(ce);
            break;    
        case CMD_LISTSCHEDULE:
            ret = adns_list_schedule(ce);
            break;
        case CMD_SCHEDULE_MODE:
            ret = adns_schedule_mode(ce);
            break;
        case CMD_LISTDOMAIN_QPS:
            ret = adns_list_qps(ce);
            break;

        /* command */
        case CMD_INITLOAD:
            ret = adns_init_load(g_adm_send_buff, g_adm_batch_offset);
            break;
        case CMD_BATCH:
            ret = adns_batch_process(g_adm_send_buff, g_adm_batch_offset);
            break;
        case CMD_REFRESH_ZONE:
            ret = adns_batch_process(g_adm_send_buff, g_adm_batch_offset);
            break;
        case CMD_REFRESH_DOMAIN:
            ret = adns_batch_process(g_adm_send_buff, g_adm_batch_offset);
            break;
        case CMD_DUMP:
            ret = adns_dump(ce);
            break;
        case CMD_CLEAR:
            ret = adns_clear(ce);
            break;     
        case CMD_SHOW:
            ret = adns_show(ce);
            break;
        case CMD_SHOW_DPDK_HEAP:
            ret = adns_show_dpdk_heap(ce);
            break;
        case CMD_STATUS:
            ret = adns_status(ce);
            break;
        case CMD_TCPSTATS:
            ret = adns_list_stats(ce);
            break;            
        case CMD_STATS:
          ret = adns_list_stats(ce);
            break;            
        case CMD_RCODE_STATS:
            ret = adns_rcode_stats(ce);
            break; 
        case CMD_PORT_STATS:
            ret = adns_dpdk_port_stats(ce);
            break;    
        case CMD_COUNTER:
            ret = adns_counter(ce);
            break;               
        case CMD_UTILI:
          ret = adns_list_utili(ce);
          break;                                                                                      
        case CMD_RELOAD_IPLIB:
            ret = adns_reload_iplib(ce);
            break;  
        case CMD_RELOAD_VM:
            ret = adns_reload_vm(ce);
            break; 
        case CMD_RELOAD_NSLIST:
            ret = adns_reload_nslist(ce);
            break;
        case CMD_SHOW_NSLIST:
            ret = adns_nslist_info(ce);
            break;
        case CMD_IP2VIEW:
        case CMD_IPV62VIEW:
            ret = adns_ip2view(ce, g_adm_view_num, g_adm_view_maps_tbl);
            break;              
        case CMD_LOOKUP:
            ret = adns_lookup(ce);
            break;       
        case CMD_QUOTA:
            ret = adns_quota(ce);
            break;       
        case CMD_LOG:
            ret = adns_log(ce);
            break;
        case CMD_53:
            ret = adns_53(ce);
            break;
        case CMD_SYSLOG:
            ret = adns_syslog(ce);
            break;
        case CMD_MEMORY_INFO:
            ret = adns_memory_info(ce);
            break;
        case CMD_SET_CNAME_CASCADE:
            ret = adns_set_cname_cascade(ce);
            break;
        case CMD_SET_WILDCARD_FALLBACK:
            ret = adns_set_wildcard_fallback(ce);
            break;
        case CMD_SET_DNSSEC:
            ret = adns_set_dnssec(ce);
            break;
        case CMD_DNSSEC_ADD_KEY:
            ret = adns_add_key(ce);
            break;
        case CMD_DNSSEC_DEL_ZSK:
            ret = adns_del_zsk(ce);
            break;
        case CMD_DNSSEC_ADD_DNSKEY_RRSIG:
            ret = adns_add_dnskey_rrsig(ce);
            break;
        case CMD_DNSSEC_QUOTA:
            ret = adns_dnssec_quota(ce);
            break;
        case CMD_DNSSEC_CACHE:
            ret = adns_dnssec_cache(ce);
            break;
        case CMD_ADDROUTE:
        case CMD_RELOADROUTE:
            ret = adns_add_reload_route(g_adm_send_buff, g_adm_batch_offset);
            break;
        case CMD_DELROUTE:
            ret = adns_del_route(ce);
            break;
        case CMD_DUMPROUTE:
            ret = adns_dump_route(ce);
            break;
        case CMD_QUIT:
          ret = adns_exit_app(ce);
          break;
        default:
            usage_exit(0);
            break;
    }

    return ret;
}


static int adm_parse_map_entry(struct adns_view_map *entry, char *line)
{
    int i;
    char *str, *token, *saveptr, *buf[5];

    for (i = 0, str = line; ; i++, str = NULL) {
        token = strtok_r(str, " ", &saveptr);
        if (token == NULL) {
            break;
        }
        
        if (i >= 3) {
            break;  
        }
        buf[i] = token;
    }

    if (i != 2) {
        fprintf(stderr, "[%s]: Invalid argment: %s\n", __FUNCTION__, line);
        return -1;
    }

    snprintf(entry->name, VIEW_NAME_LEN, "%s", buf[0]);
    entry->id = atoi(buf[1]);
    
    return 0;
}


static int adm_parse_view_map(char *file, int view_max_num, struct adns_view_map *tbl, int *view_nums)
{
    FILE *fp;
    int   ret,line_len, num = 1;   
    char  line[1024] = {0};
    struct adns_view_map *entry;

    if ((file == NULL) || (tbl == NULL)) {
        fprintf(stderr, "[%s]: File or TBL is NULL\n", __FUNCTION__);
        return -1;  
    }
    
    fp = fopen(file, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s]: Cannot open file: %s\n", __FUNCTION__, file);
        return -1;
    }

    entry = tbl;
    snprintf(line, 64, "%s", "DEFAULT 0");
    ret = adm_parse_map_entry(entry, line);
    if (ret < 0) {
        goto err;
    }

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL) {
        entry = tbl + num;
        
        line_len = strlen(line);        
        if (line_len > 0) {
            if (line[line_len - 1] == '\n') {
                line[line_len - 1] = '\0';
            }
            
            line_len = strlen(line);    
            if (line_len > 0 && line[line_len - 1] == '\r') {
                line[line_len - 1] = '\0';
            }
        }
    
        ret = adm_parse_map_entry(entry, line);
        if (ret < 0) {
            fprintf(stderr, "[%s]: Failed to parse view map: %s, line is: %d\n", __FUNCTION__, line, num + 1);
            goto err;
        }
        
        if (entry->id >= view_max_num) {
            fprintf(stderr, "[%s]: Invalid id: %s, max_view_id %d\n", __FUNCTION__, line, view_max_num);
            return -1;
        }

        num++;
        if (num >= VIEW_ID_MAX) {
            fprintf(stderr, "[%s]: View id num %d exceed max %d\n", __FUNCTION__, num, VIEW_ID_MAX);
            goto err;
        }
    }

    if (num < VIEW_ID_MIN) {
        fprintf(stderr, "[%s]: View id num %d less than min %d\n", __FUNCTION__, num, VIEW_ID_MIN);
        goto err;
    }

    *view_nums = num;
    fclose(fp);
    return 0;

err:
    fclose(fp);
    return -1;
}

static void adns_adm_log_write(int argc, char **argv, int ret, int op_msec)
{
    int i;
    size_t used_len = 0;
    struct timeval tv;
    struct tm tm;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);

    used_len += snprintf(g_buf + used_len, RET_MAX_LEN - used_len, "%02d-%02d-%04d %02d:%02d:%02d.%ld [RET=%d]:", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000, ret);
    for (i = 0; i < argc; ++i) {
        used_len += snprintf(g_buf + used_len, RET_MAX_LEN - used_len, " %s", argv[i]);
    }
    used_len += snprintf(g_buf + used_len, RET_MAX_LEN - used_len, ", %dms", op_msec);
    g_buf[used_len++] = '\n';

    write(g_fd, g_buf, used_len);

    return; 
}


int main(int argc, char **argv)
{
    int ret, op_msec;
    struct timeval start, end;
    
    gettimeofday(&start, NULL);

    ret = adm_parse_view_map(g_adm_view_map_file, VIEW_ID_MAX, g_adm_view_maps_tbl, &g_adm_view_num);
    if (ret != ADNS_ADM_OK) {
        fprintf(stderr, "Parse default view map %s ERROR!\n", g_adm_view_map_file);
        return ret;
    }

    ret = process_options(argc, argv);
    
    gettimeofday(&end, NULL);
    op_msec = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
 
    g_fd = open(g_adm_log_file, O_WRONLY | O_APPEND | O_CREAT | O_SYNC, 0666);
    if (g_fd < 0) {
        fprintf(stderr, "ERROR : open %s to write faild : %s\n", g_adm_log_file, strerror(errno));
        socket_cleanup();
        return -1;
    }

    adns_adm_log_write(argc, argv, ret, op_msec);

    close(g_fd);
    
    socket_cleanup();

    return ret;
}
