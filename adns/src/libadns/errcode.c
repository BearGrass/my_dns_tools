
#include "errcode.h"

const error_table_t adns_error_msgs[] = {
	{ ADNS_EOK, "OK" },

	/* TSIG errors. */
	{ ADNS_TSIG_EBADSIG, "Failed to verify TSIG MAC." },
	{ ADNS_TSIG_EBADKEY, "TSIG key not recognized or invalid." },
	{ ADNS_TSIG_EBADTIME, "TSIG signing time out of range." },

	/* Directly mapped error codes. */
	{ ADNS_ENOMEM, "Not enough memory." },
	{ ADNS_EINVAL, "Invalid parameter." },
	{ ADNS_ENOTSUP, "Operation not supported." },
	{ ADNS_EBUSY,   "Requested resource is busy." },
	{ ADNS_EAGAIN, "OS lacked necessary resources." },
	{ ADNS_EACCES,  "Operation not permitted." },
	{ ADNS_ECONNREFUSED, "Connection refused." },
	{ ADNS_EISCONN, "Already connected." },
	{ ADNS_EADDRINUSE, "Address already in use." },
	{ ADNS_ENOENT, "Resource not found." },
	{ ADNS_ERANGE, "Value is out of range." },

	/* General errors. */
	{ ADNS_ERROR, "General error." },
	{ ADNS_ENOTRUNNING, "Resource is not running." },
	{ ADNS_EPARSEFAIL, "Parser failed." },
	{ ADNS_ENOIPV6, "IPv6 support disabled." },
	{ ADNS_EEXPIRED, "Resource is expired." },
	{ ADNS_EUPTODATE, "Zone is up-to-date." },
	{ ADNS_EFEWDATA, "Not enough data to parse." },
	{ ADNS_ESPACE, "Not enough space provided." },
	{ ADNS_EMALF, "Malformed data." },
	{ ADNS_ECRYPTO, "Error in crypto library." },
	{ ADNS_ENSEC3PAR, "Missing or wrong NSEC3PARAM record." },
	{ ADNS_ENSEC3CHAIN, "Missing or wrong NSEC3 chain in the zone." },
	{ ADNS_EOUTOFZONE, "Name does not belong to the zone." },
	{ ADNS_EHASH, "Error in hash table." },
	{ ADNS_EZONEINVAL, "Invalid zone file." },
	{ ADNS_ENOZONE, "No such zone found." },
	{ ADNS_ENONODE, "No such node in zone found." },
	{ ADNS_ENORRSET, "No such RRSet found." },
	{ ADNS_EDNAMEPTR, "Domain name pointer larger than allowed." },
	{ ADNS_EPAYLOAD, "Payload in OPT RR larger than max wire size." },
	{ ADNS_ECRC, "CRC check failed." },
	{ ADNS_EPREREQ, "UPDATE prerequisity not met." },
	{ ADNS_ENOXFR, "Transfer was not sent." },
	{ ADNS_ENOIXFR, "Transfer is not IXFR (is in AXFR format)." },
	{ ADNS_EXFRREFUSED, "Zone transfer refused by the server." },
	{ ADNS_EDENIED, "Not allowed." },
	{ ADNS_ECONN, "Connection reset." },
	{ ADNS_EIXFRSPACE, "IXFR reply did not fit in." },
	{ ADNS_ECNAME, "CNAME loop found in zone." },
	{ ADNS_ENODIFF, "Cannot create zone diff." },
	{ ADNS_EDSDIGESTLEN, "DS digest length does not match digest type." },
	{ ADNS_ENOTSIG, "expected a TSIG or SIG(0)" },
	{ ADNS_ELIMIT, "Exceeded response rate limit." },
	{ ADNS_EWRITABLE, "File is not writable." },

	/* Control states. */
	{ ADNS_CTL_STOP, "Stopping server." },

	/* Network errors. */
	{ ADNS_NET_EADDR, "Bad address or host name." },
	{ ADNS_NET_ESOCKET, "Can't create socket." },
	{ ADNS_NET_ECONNECT, "Can't connect." },
	{ ADNS_NET_ESEND, "Can't send data." },
	{ ADNS_NET_ERECV, "Can't receive data." },
	{ ADNS_NET_ETIMEOUT, "Network timeout." },

	/* Encoding errors. */
	{ ADNS_BASE64_ESIZE, "Invalid base64 string length." },
	{ ADNS_BASE64_ECHAR, "Invalid base64 character." },
	{ ADNS_BASE32HEX_ESIZE, "Invalid base32hex string length." },
	{ ADNS_BASE32HEX_ECHAR, "Invalid base32hex character." },

	/* Key parsing errors. */
	{ ADNS_KEY_EPUBLIC_KEY_OPEN, "Cannot open public key file." },
	{ ADNS_KEY_EPRIVATE_KEY_OPEN, "Cannot open private key file." },
	{ ADNS_KEY_EPUBLIC_KEY_INVALID, "Public key file is invalid." },

	/* Key signing errors. */
	{ ADNS_DNSSEC_ENOTSUP, "Signing algorithm is not supported." },
	{ ADNS_DNSSEC_EINVALID_KEY, "The signing key is invalid." },
	{ ADNS_DNSSEC_EASSIGN_KEY, "Cannot assign the key." },
	{ ADNS_DNSSEC_ECREATE_DIGEST_CONTEXT, "Cannot create digest context." },
	{ ADNS_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE, "Unexpected signature size." },
	{ ADNS_DNSSEC_EDECODE_RAW_SIGNATURE, "Cannot decode the raw signature." },
	{ ADNS_DNSSEC_ESIGN, "Cannot create the signature." },

	{ ADNS_ERROR, 0 } /* Terminator */
};

