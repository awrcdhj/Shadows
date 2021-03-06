#!/bin/bash

#获取url
echo "url:"
read url

#获取ip
echo "ip:"
read ip

#向/etc/named.rfc1912.zones尾插入
#zone "$url" IN {
#       type master;
#       file "$url.zone";
#        allow-update{ none; };
#};

cat>>/etc/named.rfc1912.zones<<EOF

zone "$url" IN {
       type master;
       file "$url.zone";
       allow-update{ none; };
};
EOF

#复制生成文件
cp -a /var/named/named.localhost /var/named/${url}.zone

#向/var/named/${url}.zone中插入
#$TTL 1D
#@      IN SOA  $url admin.$url. (
#                                       0       ; serial
#                                       1D      ; refresh
#                                       1H      ; retry
#                                       1W      ; expire
#                                       3H )    ; minimum
#       NS      datav.aliyuncs.com.
#       A       $ip


cat>/var/named/${url}.zone<<EOF
\$TTL 1D
@       IN SOA  $url admin.$url. (
                                        0       ; serial
                                        1D      ; refresh
                                        1H      ; retry
                                        1W      ; expire
                                        3H )    ; minimum
        NS      $url.
        A       $ip
EOF


#完成
echo "$url $ip complete"
{
var<'a'>=i;//虚数变量
var<'b'>=DNS;//等同于DNSIP 参考正文列表赋值传递
var<'d'>=DOH;//DNS OVER HTTPS 取值见上
var<'v'>=variable;//VAR变量
var-9000;//线程监听数目
<script>

w-quantifying= `102

k-quantifying= `26

generic=`[Host]

route= `(/vat/Host/body/response/configuration/my-configuration() )

response= `configuration()

encapsulation= `response

starting `abk&v`variable(-v) === var {
print{variable}file{

End{quote file}'reload {
$done({var}) 

starting}var@[Host] ~${ DNSDomainName -v& (configuration() )
$done(my-configuration)
}
GETHostname()= `AY1307311912260196fcZ’

Result: h_name=`AY1307311912260196fcZ

response= `body()’

element= `h_name’

response: h_adds_list= `224.0.0.251'

configuration= `DNS'

response= `my-configuration ()
</script>
<body>
configuration: {

DNS= `( "2620:74:10:2800::45" )

DNS= `( "2620:74:14:3000::40" )

DNS= `( "2A05:D016:AF8:4000:7710:6FC:BDE3:FE0E" )

DNS= `( "2001:41d0:302:2200::180" )

DNS= `( "2a04:bdc7:100:70::70" )

DNS= `( "2a00:5980:94::71" )

DNS= `( "2400:8904:e001:43::43" )

DNS= `( "2001:bc8:1824:738::1" )

DNS= `( "2001:bc8:1830:2018::1" )

DNS= `( "2a04:5200:fff4::13ff" )

DNS= `( "2001:bc8:1824:738::1" )

DNS= `( "8.26.56.26" )

DNS= `( "8.20.247.20" )

DNS= `( "69.58.187.40" )

DNS= `( "209.131.162.45" )

DNS= `( "94.140.14.14" )

DNS= `( "176.103.130.130" )

DNS= `( "94.140.14.140" )

DNS= `( "45.67.219.208" )

DNS= `( "8.20.247.2" )

DNS= `( "112.48.162.8" )

DNS= `( "112.124.47.27" )

DNS= `("114.215.126.16")

DNS= `( "119.29.29.29" )

DNS= `( "74.82.42.42" )

DNS= `( "1.2.4.8" )

DNS= `( "210.2.4.8" )

DNS= `( "223.5.5.5" )

DNS= `( "223.6.6.6" )

DNS= `( "115.159.96.69" )

DNS= `( "122.114.245.45" )

DNS= `( "119.28.28.28" )

DNS= `( "1.1.1.1" )

DNS= `( "1.0.0.1" )

DNS= `( "208.67.222.222" )

DNS= `( "208.67.222.220" )

DNS= `( "123.207.137.88" )

DNS= `( "95.181.155.140" )

DNS= `( "51.15.124.208" )

DNS= `( "45.79.120.233" )

DNS= `( "185.253.154.66" )

DNS= `( "185.194.94.71" )

DNS= `( "185.228.168.10" )

DNS= `( "193.70.85.11" )

DNS= `( "13.49.175.86" )

DNS= `( "104.155.237.225" )

DNS= `( "208.67.220.220" )

DNS= `( "1.1.1.2" )

DNS= `( "1.0.0.2" )

DNS= `( "95.217.213.94" )

DNS= `( "212.78.94.4" )

DNS= `( "23.226.134.242" )

DNS= `( "182.254.116.116" )

DNS= `( "156.154.70.1" )

DNS= `( "180.76.76.76" )

DNS= `( "182.254.116.116" )

DNS= `( "101.101.101.101" )

DNS= `( "101.102.103.104" )

DNS= `( "80.80.80.80" )

DNS= `( "80.80.81.81" )

DNS= `( "4.2.2.1" )

DNS= `( "4.2.2.2" )

DNS= `( "210.2.1.1" )

DNS= `( "210.2.2.2" )

DNS= `( "13.49.175.86" )

DNS= `( "104.21.57.110" )

DNS= `( "172.67.145.168" )

DNS= `( "37.120.152.235" )

DNS= `( "37.120.236.11" )

DNS= `( "37.120.142.115" )

DNS= `( "37.120.232.43" )

DNS= `( "45.153.187.96" )

DNS= `( "72.11.134.90" )

DNS= `( "77.88.8.78" )

DNS= `( "217.169.20.23" )

DNS= `( "51.158.166.97" )

DNS= `( "149.154.153.153" )

DNS= `( "5.2.75.75" )

DNS= `( "218.30.118.6" )

DNS= `( "115.159.220.214" )

DNS= `( "115.157.157.26" )

DNS= `( "115.159.158.38" )

DNS= `( "202.141.162.123" )

DNS= `( "202.38.93.153" )

DNS= `( "202.141.176.93" )

DNS= `( "168.95.192.1" )

DNS= `( "168.95.1.1" )

DNS= `( "115.159.146.99" )

DNS= `( "123.206.51.48" )

DNS= `( "115.159.157.26" )

DNS= `( "115.159.158.38" )

DNS= `( "106.14.152.170" )

DNS= `( "63.223.94.66" )

DNS= `( "203.80.96.10" )

DNS= `( "203.80.96.9" )

DNS= `( "112.121.178.187" )

DNS= `( "123.206.61.167" )'

DNS= `( "119.29.105.234" )

DNS= `( "223.113.97.99" )

DNS= `( "123.125.81.6" )

DNS= `( "140.207.198.6" )

DNS= `( "103.16.131.77" )
 }$done(configuration)
[DOH]
my-configuration: {

DOH= `( "https://doh-jp.blahdns.com/dns-query" )

DOH= `( "https://doh-jp.blahdns.com/dns-query" )

DOH= `( "https:/doh.la.ahadns.net/dns-query" )

DOH= `( "https:/adfree.usableprivacy.net/dns-query" )

DOH= `( "https:/dnsnl.alekberg.net/dns-query" )

DOH= `( "https:/dns.adguard.com/dns-query" )

DOH= `( "https:/dns.circl.lu.com/dns-query" )

DOH= `( "https://dns.gooele.com/dns-query" )

DOH= `( "https://dns.wevpn.com/dns-query" )

DOH= `( "https://dns-weblock.wevpn.com/dns-query" )

DOH= `( "https://dns.adguard.com/dns-query" )

DOH= `( "https://dns-family.adguard.com/dns-query" )

DOH= `( "https://doh.in.ahadns.net/dns-query" )

DOH= `( "https://doh.la.ahadns.net/dns-query" )

DOH= `( "https://doh.nl.ahadns.net/dns-query" )

DOH= `( "https://dns.aa.net.uk/dns-query" )

DOH= `( "https://doh.applied-privacy.net/query" )

DOH= `( "https://dns64.dns.google/dns-query" )

DOH= `( "https://dns10.quad9.net/dns-query" )

DOH= `( "https://doh.doh.my.id/dns-query" )

DOH= `( "https://doh-de.blahdns.com/dns-query" )

DOH= `( "https://doh.pub/dns-query" )

DOH= `( "https://rubyfish.com/dns-query" )

DOH= `( "https://dns.rubyfish.com/dns-query" )

DOH= `( "https://doh.xeton.com/dns-query" )

DOH= `( "https://doh.bortzmeyer.fr/dns-query" )

DOH= `( "https://dns.brahma.world/dns-query" )

DOH= `( "https://dnsse.alekberg.net/dns-query" )

DOH= `( "https://av1.nstld.com/dns-query" )

DOH= `( "https://av2.nstld.com/dns-query" )

DOH= `( "https://av3.nstld.com/dns-query" )

DOH= `( "https://av4.nstld.com/dns-query" )

DOH= `( "https://dns.aa.net.uk/dns-query" )

DOH= `( "https://whois.verisign-grs.com/dns-query" )

DOH= `( "https:/23.226.134.242.static.quadranet.com/dns-query" )
}$done(my-configuration)
}}
</body>

if End {
end ~var&&do
}$done()
