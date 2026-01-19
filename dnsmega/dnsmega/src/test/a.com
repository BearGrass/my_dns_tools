$ORIGIN .
$TTL 86400	; 1 day
a.com			IN SOA	163.cn. root.163.cn. (
				1997022704 ; serial
				28800      ; refresh (8 hours)
				14400      ; retry (4 hours)
				3600000    ; expire (5 weeks 6 days 16 hours)
				86400      ; minimum (1 day)
				)
			NS	ns.a.com.
			A	10.97.212.33
$ORIGIN a.com.
*			A	10.97.212.33
$TTL 60	; 1 minute
b			CNAME	mogu.com.
confreg.0000000001-0000014385-0000014383.dev01.alipay.net A 1.1.1.1
$TTL 600	; 10 minutes
liyong			A	2.2.2.2
mogu            A   10.178.137.172
mogu            A   11.176.211.41
mogu            A   10.176.27.132
mogu            A   11.184.149.68
mogu            A   11.131.132.201
mogu            A   11.131.132.15
mogu            A   11.183.170.189
mogu            A   11.183.170.86
mogu            A   11.131.133.208
mogu            A   10.176.27.146
mogu            A   10.176.27.135
mogu            A   11.131.133.205
mogu            A   11.176.211.40
mogu            A   11.230.140.53
mogu            A   10.176.27.147
mogu            A   11.183.170.84
mogu            A   10.176.27.148
mogu            A   11.131.133.204
mogu            A   10.176.27.130
mogu            A   10.176.27.131
mogu            A   11.183.148.161
mogu            A   11.186.50.158
mogu            A   10.176.27.134
mogu            A   10.176.16.65
mogu            A   10.176.27.144
mogu            A   10.178.137.175
mogu            A   10.176.27.52
mogu            A   11.183.170.185
mogu            A   11.183.148.160
mogu            A   10.176.27.101
mogu            A   10.176.27.102
mogu            A   10.176.27.103
mogu            A   10.176.27.104
mogu            A   10.176.27.105
mogu            A   10.176.27.106
mogu            A   10.176.27.107
mogu            A   10.176.27.108
mogu            A   10.176.27.109
mogu            A   10.176.27.111
mogu            A   10.176.27.121
mogu            A   10.176.27.131
mogu            A   10.176.27.141
mogu            A   10.176.27.151
mogu            A   10.176.27.161
mogu            A   10.176.27.171
mogu            A   10.176.27.181
mogu            A   10.176.27.191
mogu            A   10.176.27.101
mogu            A   10.176.27.201
mogu            A   10.176.27.101
mogu            A   10.176.27.11
mogu            A   10.176.27.12
mogu            A   10.176.27.13
mogu            A   10.176.27.14
