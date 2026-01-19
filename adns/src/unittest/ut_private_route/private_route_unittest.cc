#include "gtest/gtest.h"


extern "C"{
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>    
    #include "private_route.h"
    #include "adns_conf.h"
}
using namespace std;

static adns_ipset_t *ipset_init(uint16_t ips_num)
{
    adns_ipset_t *ipset = NULL;

    ipset = (adns_ipset_t *)malloc(sizeof(adns_ipset_t));
    if (ipset == NULL) {
        return NULL;
    }
    memset(ipset, 0, sizeof(adns_ipset_t));

    ipset->info4 = (adns_ipset_ipv4_info_t *)malloc(ips_num * sizeof(adns_ipset_ipv4_info_t));
    if (ipset->info4 == NULL) {
        free(ipset);
        return NULL;
    }
    
    ipset->ips_cap = ips_num;
    ipset->max_route_id = ips_num;

    return ipset;
}

class Private_Route_Test : public testing::Test
{
protected:
    static void SetUpTestCase()
    {
        cout << "************* this is the start of private route unittest ***********" << endl;
    }
    static void TearDownTestCase()
    {
        cout << "************* this is the end of private route unittest ************" << endl;
    }
};

TEST_F(Private_Route_Test, adns_ipset_init_err_test)
{
    int ret;

    adns_ipset_t *ipset =  ipset_init(19);
    EXPECT_EQ(NULL, !ipset);
    EXPECT_EQ(NULL, !ipset->info4);
    EXPECT_EQ(0, ipset->ips_num);
    EXPECT_EQ(19, ipset->ips_cap);
    EXPECT_EQ(19, ipset->max_route_id);

    ret = adns_ipset_init(NULL, "ip_range_cal_mask_test.map");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(0, ipset->ips_num);

    ret = adns_ipset_init(ipset, NULL);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(0, ipset->ips_num);

    ret = adns_ipset_init(ipset, "non-existent.map");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(0, ipset->ips_num);

    ret = adns_ipset_init(ipset, "ip_range_cal_mask_test.map");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(0, ipset->ips_num);

    free(ipset->info4);
    free(ipset);

    ipset = ipset_init(20);
    EXPECT_EQ(NULL, !ipset);
    EXPECT_EQ(NULL, !ipset->info4);
    EXPECT_EQ(0, ipset->ips_num);
    EXPECT_EQ(20, ipset->ips_cap);
    EXPECT_EQ(20, ipset->max_route_id);
    ret = adns_ipset_init(ipset, "ip_range_viewid_err.map");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(0, ipset->ips_num);

    free(ipset->info4);
    free(ipset);
}

TEST_F(Private_Route_Test, adns_ipset_init_test)
{
    int ret;
    adns_ipset_ipv4_info_t info4;

    adns_ipset_t *ipset =  ipset_init(20);
    EXPECT_EQ(NULL, !ipset);
    EXPECT_EQ(NULL, !ipset->info4);
    ASSERT_EQ(20, ipset->ips_cap);
    ASSERT_EQ(0, ipset->ips_num);

    ret = adns_ipset_init(ipset, "ip_range_cal_mask_test.map");
    ASSERT_EQ(0, ret);
    ASSERT_EQ(20, ipset->ips_num);

    info4 = ipset->info4[0];
    EXPECT_EQ(0, info4.ips_head);
    EXPECT_EQ(16777215, info4.ips_tail);
    EXPECT_EQ(0, info4.id);

    info4 = ipset->info4[1];
    EXPECT_EQ(16777216, info4.ips_head);
    EXPECT_EQ(16777471, info4.ips_tail);
    EXPECT_EQ(1, info4.id);
    
    info4 = ipset->info4[2];
    EXPECT_EQ(16777472, info4.ips_head);
    EXPECT_EQ(16778239, info4.ips_tail);
    EXPECT_EQ(2, info4.id);
   
    info4 = ipset->info4[3];
    EXPECT_EQ(16778240, info4.ips_head);
    EXPECT_EQ(16779263, info4.ips_tail);
    EXPECT_EQ(3, info4.id);
    
    info4 = ipset->info4[4];
    EXPECT_EQ(16779264, info4.ips_head);
    EXPECT_EQ(16781311, info4.ips_tail);
    EXPECT_EQ(4, info4.id);
    
    info4 = ipset->info4[5];
    EXPECT_EQ(16781312, info4.ips_head);
    EXPECT_EQ(16785407, info4.ips_tail);
    EXPECT_EQ(5, info4.id);
    
    info4 = ipset->info4[6];
    EXPECT_EQ(16785408, info4.ips_head);
    EXPECT_EQ(16793599, info4.ips_tail);
    EXPECT_EQ(6, info4.id);
  
    info4 = ipset->info4[7];
    EXPECT_EQ(16793600, info4.ips_head);
    EXPECT_EQ(16809983, info4.ips_tail);
    EXPECT_EQ(7, info4.id);
    
    info4 = ipset->info4[8];
    EXPECT_EQ(16809984, info4.ips_head);
    EXPECT_EQ(16810111, info4.ips_tail);
    EXPECT_EQ(8, info4.id);
    
    info4 = ipset->info4[9];
    EXPECT_EQ(16810112, info4.ips_head);
    EXPECT_EQ(16810175, info4.ips_tail);
    EXPECT_EQ(9, info4.id);
    
    info4 = ipset->info4[10];
    EXPECT_EQ(16810176, info4.ips_head);
    EXPECT_EQ(16811007, info4.ips_tail);
    EXPECT_EQ(10, info4.id);
    
    info4 = ipset->info4[11];
    EXPECT_EQ(16811008, info4.ips_head);
    EXPECT_EQ(16811199, info4.ips_tail);
    EXPECT_EQ(11, info4.id);
    
    info4 = ipset->info4[12];
    EXPECT_EQ(16811200, info4.ips_head);
    EXPECT_EQ(16811263, info4.ips_tail);
    EXPECT_EQ(12, info4.id);
    
    info4 = ipset->info4[13];
    EXPECT_EQ(16811264, info4.ips_head);
    EXPECT_EQ(16811775, info4.ips_tail);
    EXPECT_EQ(13, info4.id);
    
    info4 = ipset->info4[14];
    EXPECT_EQ(16811776, info4.ips_head);
    EXPECT_EQ(16811903, info4.ips_tail);
    EXPECT_EQ(14, info4.id);
   
    info4 = ipset->info4[15];
    EXPECT_EQ(16811904, info4.ips_head);
    EXPECT_EQ(16812031, info4.ips_tail);
    EXPECT_EQ(15, info4.id);
    
    info4 = ipset->info4[16];
    EXPECT_EQ(16812032, info4.ips_head);
    EXPECT_EQ(16812287, info4.ips_tail);
    EXPECT_EQ(16, info4.id);
    
    info4 = ipset->info4[17];
    EXPECT_EQ(16812288, info4.ips_head);
    EXPECT_EQ(16812543, info4.ips_tail);
    EXPECT_EQ(17, info4.id);
    
    info4 = ipset->info4[18];
    EXPECT_EQ(16812544, info4.ips_head);
    EXPECT_EQ(16812863, info4.ips_tail);
    EXPECT_EQ(18, info4.id);
    
    info4 = ipset->info4[19];
    EXPECT_EQ(16812864, info4.ips_head);
    EXPECT_EQ(16812927, info4.ips_tail);
    EXPECT_EQ(19, info4.id);
    
    free(ipset->info4);
    free(ipset);
}

TEST_F(Private_Route_Test, ipset_lookup_test)
{
    int ret;
    adns_private_route_id_t view_id = 0;

    adns_ipset_t *ipset =  ipset_init(20);
    EXPECT_EQ(NULL, !ipset);
    EXPECT_EQ(NULL, !ipset->info4);
    ASSERT_EQ(0, ipset->ips_num);
    ASSERT_EQ(20, ipset->ips_cap);

    ret = adns_ipset_init(ipset, "ip_range_cal_mask_test.map");
    EXPECT_EQ(0, ret);
    ASSERT_EQ(20, ipset->ips_num);

    /* miss match ipset */
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.139.128"));
    EXPECT_EQ(IPSET_LOOKUP_MISS, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("30.0.0.0"));
    EXPECT_EQ(IPSET_LOOKUP_MISS, view_id);

    /* hit view 0 */
    view_id = adns_ipset_lookup(ipset, inet_addr("0.0.0.0"));
    EXPECT_EQ(0, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("0.255.255.255"));
    EXPECT_EQ(0, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("0.255.128.0"));
    EXPECT_EQ(0, view_id);

    /* hit view 1*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.0.0"));
    EXPECT_EQ(1, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.0.255"));
    EXPECT_EQ(1, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.0.128"));
    EXPECT_EQ(1, view_id);

    /* hit view 2*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.1.0"));
    EXPECT_EQ(2, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.3.255"));
    EXPECT_EQ(2, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.3.0"));
    EXPECT_EQ(2, view_id);

    /* hit view 3*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.4.0"));
    EXPECT_EQ(3, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.7.255"));
    EXPECT_EQ(3, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.6.128"));
    EXPECT_EQ(3, view_id);

    /* hit view 4*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.8.0"));
    EXPECT_EQ(4, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.15.255"));
    EXPECT_EQ(4, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.10.128"));
    EXPECT_EQ(4, view_id);

    /* hit view 5*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.16.0"));
    EXPECT_EQ(5, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.31.255"));
    EXPECT_EQ(5, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.25.128"));
    EXPECT_EQ(5, view_id);

    /* hit view 6*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.32.0"));
    EXPECT_EQ(6, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.63.255"));
    EXPECT_EQ(6, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.45.128"));
    EXPECT_EQ(6, view_id);

    /* hit view 7*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.64.0"));
    EXPECT_EQ(7, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.127.255"));
    EXPECT_EQ(7, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.100.128"));
    EXPECT_EQ(7, view_id);

    /* hit view 8*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.0"));
    EXPECT_EQ(8, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.127"));
    EXPECT_EQ(8, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.1"));
    EXPECT_EQ(8, view_id);

    /* hit view 9*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.128"));
    EXPECT_EQ(9, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.191"));
    EXPECT_EQ(9, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.164"));
    EXPECT_EQ(9, view_id);

    /* hit view 10 */
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.128.192"));
    EXPECT_EQ(10, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.131.255"));
    EXPECT_EQ(10, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.130.255"));
    EXPECT_EQ(10, view_id);

    /* hit view 11 */
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.0"));
    EXPECT_EQ(11, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.191"));
    EXPECT_EQ(11, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.128"));
    EXPECT_EQ(11, view_id);

    /* hit view 12 */
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.192"));
    EXPECT_EQ(12, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.255"));
    EXPECT_EQ(12, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.132.254"));
    EXPECT_EQ(12, view_id);

    /* hit view 13*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.133.0"));
    EXPECT_EQ(13, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.134.255"));
    EXPECT_EQ(13, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.133.128"));
    EXPECT_EQ(13, view_id);

    /* hit view 14*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.0"));
    EXPECT_EQ(14, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.127"));
    EXPECT_EQ(14, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.64"));
    EXPECT_EQ(14, view_id);

    /* hit view 15*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.128"));
    EXPECT_EQ(15, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.255"));
    EXPECT_EQ(15, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.135.192"));
    EXPECT_EQ(15, view_id);

    /* hit view 16*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.136.0"));
    EXPECT_EQ(16, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.136.255"));
    EXPECT_EQ(16, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.136.192"));
    EXPECT_EQ(16, view_id);

    /* hit view 17*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.137.0"));
    EXPECT_EQ(17, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.137.255"));
    EXPECT_EQ(17, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.137.128"));
    EXPECT_EQ(17, view_id);

    /* hit view 18*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.138.0"));
    EXPECT_EQ(18, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.139.63"));
    EXPECT_EQ(18, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.138.255"));
    EXPECT_EQ(18, view_id);

    /* hit view 19*/
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.139.64"));
    EXPECT_EQ(19, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.139.127"));
    EXPECT_EQ(19, view_id);
    view_id = adns_ipset_lookup(ipset, inet_addr("1.0.139.100"));
    EXPECT_EQ(19, view_id);

    free(ipset->info4);
    free(ipset);
}
