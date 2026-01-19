
#include "consts.h"

#if 0
adns_lookup_table_t adns_opcode_names[] = {
	{ ADNS_OPCODE_QUERY,  "QUERY" },
	{ ADNS_OPCODE_IQUERY, "IQUERY" },
	{ ADNS_OPCODE_STATUS, "STATUS" },
	{ ADNS_OPCODE_NOTIFY, "NOTIFY" },
	{ ADNS_OPCODE_UPDATE, "UPDATE" },
	{ 0, NULL }
};

adns_lookup_table_t adns_rcode_names[] = {
	{ ADNS_RCODE_NOERROR,  "NOERROR" },
	{ ADNS_RCODE_FORMERR,  "FORMERR" },
	{ ADNS_RCODE_SERVFAIL, "SERVFAIL" },
	{ ADNS_RCODE_NXDOMAIN, "NXDOMAIN" },
	{ ADNS_RCODE_NOTIMPL,  "NOTIMPL" },
	{ ADNS_RCODE_REFUSED,  "REFUSED" },
	{ ADNS_RCODE_YXDOMAIN, "YXDOMAIN" },
	{ ADNS_RCODE_YXRRSET,  "YXRRSET" },
	{ ADNS_RCODE_NXRRSET,  "NXRRSET" },
	{ ADNS_RCODE_NOTAUTH,  "NOTAUTH" },
	{ ADNS_RCODE_NOTZONE,  "NOTZONE" },
	{ ADNS_RCODE_BADSIG,   "BADSIG" },
	{ ADNS_RCODE_BADKEY,   "BADKEY" },
	{ ADNS_RCODE_BADTIME,  "BADTIME" },
	{ ADNS_RCODE_BADMODE,  "BADMODE" },
	{ ADNS_RCODE_BADNAME,  "BADNAME" },
	{ ADNS_RCODE_BADALG,   "BADALG" },
	{ ADNS_RCODE_BADTRUNC, "BADTRUNC" },
	{ 0, NULL }
};

adns_lookup_table_t adns_tsig_alg_names[] = {
	{ ADNS_TSIG_ALG_HMAC_MD5,    "hmac-md5" },
	{ ADNS_TSIG_ALG_HMAC_SHA1,   "hmac-sha1" },
	{ ADNS_TSIG_ALG_HMAC_SHA224, "hmac-sha224" },
	{ ADNS_TSIG_ALG_HMAC_SHA256, "hmac-sha256" },
	{ ADNS_TSIG_ALG_HMAC_SHA384, "hmac-sha384" },
	{ ADNS_TSIG_ALG_HMAC_SHA512, "hmac-sha512" },
	{ ADNS_TSIG_ALG_NULL, NULL }
};

adns_lookup_table_t adns_tsig_alg_dnames_str[] = {
	{ ADNS_TSIG_ALG_GSS_TSIG,    "gss-tsig." },
	{ ADNS_TSIG_ALG_HMAC_MD5,    "hmac-md5.sig-alg.reg.int." },
	{ ADNS_TSIG_ALG_HMAC_SHA1,   "hmac-sha1." },
	{ ADNS_TSIG_ALG_HMAC_SHA224, "hmac-sha224." },
	{ ADNS_TSIG_ALG_HMAC_SHA256, "hmac-sha256." },
	{ ADNS_TSIG_ALG_HMAC_SHA384, "hmac-sha384." },
	{ ADNS_TSIG_ALG_HMAC_SHA512, "hmac-sha512." },
	{ ADNS_TSIG_ALG_NULL, NULL }
};

adns_lookup_table_t adns_tsig_alg_dnames[] = {
        { ADNS_TSIG_ALG_GSS_TSIG,    "\x08" "gss-tsig" },
        { ADNS_TSIG_ALG_HMAC_MD5,    "\x08" "hmac-md5" "\x07" "sig-alg" "\x03" "reg" "\x03" "int" },
	{ ADNS_TSIG_ALG_HMAC_SHA1,   "\x09" "hmac-sha1" },
	{ ADNS_TSIG_ALG_HMAC_SHA224, "\x0B" "hmac-sha224" },
	{ ADNS_TSIG_ALG_HMAC_SHA256, "\x0B" "hmac-sha256" },
	{ ADNS_TSIG_ALG_HMAC_SHA384, "\x0B" "hmac-sha384" },
	{ ADNS_TSIG_ALG_HMAC_SHA512, "\x0B" "hmac-sha512" },
	{ ADNS_TSIG_ALG_NULL, NULL }
};

size_t adns_tsig_digest_length(const uint8_t algorithm)
{
	switch (algorithm) {
	case ADNS_TSIG_ALG_GSS_TSIG:
		return ADNS_TSIG_ALG_DIG_LENGTH_GSS_TSIG;
	case ADNS_TSIG_ALG_HMAC_MD5:
		return ADNS_TSIG_ALG_DIG_LENGTH_HMAC_MD5;
	case ADNS_TSIG_ALG_HMAC_SHA1:
		return ADNS_TSIG_ALG_DIG_LENGTH_SHA1;
	case ADNS_TSIG_ALG_HMAC_SHA224:
		return ADNS_TSIG_ALG_DIG_LENGTH_SHA224;
	case ADNS_TSIG_ALG_HMAC_SHA256:
		return ADNS_TSIG_ALG_DIG_LENGTH_SHA256;
	case ADNS_TSIG_ALG_HMAC_SHA384:
		return ADNS_TSIG_ALG_DIG_LENGTH_SHA384;
	case ADNS_TSIG_ALG_HMAC_SHA512:
		return ADNS_TSIG_ALG_DIG_LENGTH_SHA512;
	default:
		return 0;
	}
}

size_t adns_ds_digest_length(const uint8_t algorithm)
{
	switch (algorithm) {
	case ADNS_DS_ALG_SHA1:
		return ADNS_DS_DIGEST_LEN_SHA1;
	case ADNS_DS_ALG_SHA256:
		return ADNS_DS_DIGEST_LEN_SHA256;
	case ADNS_DS_ALG_GOST:
		return ADNS_DS_DIGEST_LEN_GOST;
	case ADNS_DS_ALG_SHA384:
		return ADNS_DS_DIGEST_LEN_SHA384;
	default:
		return 0;
	}
}
#endif
