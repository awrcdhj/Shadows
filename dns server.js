#  TITLE=Concurrent parsing of DNS server
#  DNS_SERVER_TOTAL_LINES=130

address/@server:/

VAR=1000
echo | awk -v VARIABLE=$VAR '{ print VARIABLE } END{ print "end" }' file
awk '( BEGIN VARIABLE=&server:/)
LocalHost-matching-domainname=true
LocalHost=server:/
                /=server:/
/119.29.29.29
/74.82.42.42
/1.2.4.8
/210.2.4.8
/223.5.5.5
/223.6.6.6
/119.28.28.28
/1.1.1.1
/1.0.0.1
/180.76.76.76
/182.254.116.116
/101.101.101.101
/101.102.103.104
/80.80.80.80
/80.80.81.81
/4.2.2.1
/4.2.2.2
/112.121.178.187
/203.80.96.10
/203.80.96.9
/123.206.61.167
/119.29.105.234
/223.113.97.99
/123.125.81.6
/140.207.198.6
/115.159.157.26 
/115.159.158.38
/103.16.131.77
/13.49.175.86
/104.21.57.110
/172.67.145.168
/8.20.247.2
/37.120.152.235
/37.120.236.11
/37.120.142.115
/37.120.232.43
/45.153.187.96
/72.11.134.90
/77.88.8.78
/217.169.20.23
/51.158.166.97
/149.154.153.153
/94.140.14.14
/176.103.130.130
/94.140.14.15
/176.103.130.132
/94.140.14.140
/45.67.219.208
/5.2.75.75
/95.181.155.140
/51.15.124.208
/45.79.120.233
/185.253.154.66
/193.70.85.11
/13.49.175.86
/104.155.237.225
/185.194.94.71
/208.67.220.220
/185.228.168.10
/1.1.1.3
/1.0.0.3
/95.217.213.94
/212.78.94.4
/23.226.134.242
/182.254.116.116
/80.80.81.81
/80.80.80.80
/210.2.1.1
/210.2.2.2
/101.226.4
/218.30.118.6
/208.67.222.222
/208.67.222.220