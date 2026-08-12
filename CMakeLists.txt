cmake_minimum_required(VERSION 3.5)
project(InternetApplications)

set(CMAKE_C_STANDARD 99)

add_executable(l3-exec1 l3-exec1.c)
add_executable(l3-fork1 l3-fork1.c)
add_executable(l3-fork2 l3-fork2.c)
add_executable(l3-lseek1 l3-lseek1.c)
add_executable(l3-readwrite1 l3-readwrite1.c)
add_executable(l3-signal1 l3-signal1.c)
add_executable(l4-1 l4-1.c)
add_executable(l4-2 l4-2.c)
add_executable(l5 l5.c)
add_executable(l6-EchoClient l6-EchoClient.c)
add_executable(l6-EchoServer l6-EchoServer.c)
add_executable(l7-Client l7-Client.c)
add_executable(l7-Server l7-Server.c)

add_executable(dhcp-client DHCP-Project/dhcp-client.c)
add_executable(dhcp-server DHCP-Project/dhcp-server.c)
target_include_directories(dhcp-client PRIVATE DHCP-Project)
target_include_directories(dhcp-server PRIVATE DHCP-Project)

add_executable(dns-client DNS-Project/dns-client.c)
add_executable(dns-local-server DNS-Project/dns-local-server.c)
add_executable(dns-root-server DNS-Project/dns-root-server.c)
add_executable(dns-root-server-arpa DNS-Project/dns-root-server-arpa.c)
add_executable(dns-tld-server-a DNS-Project/dns-tld-server-a.c)
add_executable(dns-tld-server-b DNS-Project/dns-tld-server-b.c)
add_executable(dns-second-server-a DNS-Project/dns-second-server-a.c)
add_executable(dns-second-server-b DNS-Project/dns-second-server-b.c)

foreach(dns_target
    dns-client
    dns-local-server
    dns-root-server
    dns-root-server-arpa
    dns-tld-server-a
    dns-tld-server-b
    dns-second-server-a
    dns-second-server-b
)
    target_include_directories(${dns_target} PRIVATE DNS-Project)
endforeach()
