Multi-Threaded-DNS-client
=========================

Multi Threaded DNS client with internal Caching of dns entries


1. I have used pthread api for mutex locks and creating threads.
2. Main input file is mmaped in memory (file name :hostneames)
3. above file is mapped at address "addr_main_file"
4. Each worker thread works on specific part of input file based upon its thread id.
             start_addr=addr_main_file+(tid-1)*size;
             end_addr=addr_main_file+(tid)*size;
    start_addr and end_addr is adjusted to nearest host names
5. Each worker thread has their own tmp file (file_name: thread_threadid) for saving their output, these files get deleted after program ends.
6. Each worker thread creates socket, make dns query, send dns query using UDP, receive response of query, parse the query and put the output in their tmp file
7. After worker threads have finished their work, the tmp files are combined to make output file

About  Cache
1. I have implemented LRU based internal cache.
2. Used Hash Tables and queue for Maintaining LRU Tables
3. Cache can be configured for any number of enteries to be cached
    currently I am caching 100 entries
       #define CACHE_CAPACITY 100
4. Each worker thread access cache by taking locks
                // if access cache returns 0 --> Cache miss 
                // if access cache returns 1 --> Cache hit
                pthread_mutex_lock(&access_cache_mutex);
                cache_output=access_cache(file_host);
                pthread_mutex_unlock(&access_cache_mutex);
                if(cache_output==1)
                        continue;

About dns server configuration

see function "void configure_dns_servers()"

1. In this I have configured 17 free dns servers
2. set number of dns server you want to use
   currently I am using 2 dns servers
   #define DNS_SERVERS_TO_USE 2
3. See dns servers list in function "configure_dns_servers()"
4. Each worker thread chooses dns server according to their thread id
        dns_num=tid%num_dns_servers;
        dest.sin_addr.s_addr=inet_addr(dns_servers[dns_num]);


Test Cases
I Have test my code with duplicate entries and also normal enteries, It is working fine. for this i have created 5 threads

I have also tested using alexa to 10 million entries with 50 threads. It is working fine
