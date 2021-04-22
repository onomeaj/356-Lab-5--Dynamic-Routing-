# 356-Lab-5--Dynamic-Routing-
To run manually (each in a separate tab/terminal instance):

 IN LAB5 DIRECTORY:
 
./run_pox.sh

./run_mininet.sh

IN ROUTER DIRECTORY:

no segfaults happening:

./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost1

./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost2

./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost3

segfaults are/may be occurring:

valgrind --leak-check=full ./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost1

valgrind --leak-check=full ./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost2

valgrind --leak-check=full ./sr -t 300 -s 127.0.0.1 -p 8888 -v vhost3

