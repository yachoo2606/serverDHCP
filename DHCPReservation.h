//DHCPReservation.h

#ifndef DHCPRESERVATION_H
#define DHCPRESERVATION_H

#include <iostream>
#include <chrono>
#include <arpa/inet.h>


enum class Status{
    NONE,
    IN_PROCESS,
    RESERVED
};

class DHCPReservation{
    Status status;
    unsigned char chaddr[16];
    struct in_addr ip;
    std::chrono::seconds leeseInSeconds;
public:

    DHCPReservation(int seconds, unsigned char *address, Status status_,const char* ipAddress);
    DHCPReservation();
    ~DHCPReservation();

    Status getStatus() const;

    void setStatus(Status newStatus);

    const unsigned char* getChaddr() const;

    void setChaddr(const unsigned char* address);

    std::chrono::seconds getLeaseInSeconds();

    void setLeaseInSeconds(int seconds);

    const char* getIpAddress_string() const;

    struct in_addr getIpAddress() const;

    void setIpAddress(const char* ipAddress);

    void print_mac_address();

    void decreseLeese();

};

#endif // DHCPRESERVATION_H