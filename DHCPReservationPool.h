
#ifndef DHCPRESERVATIONPOOL_H
#define DHCPRESERVATIONPOOL_H

#include <iostream>
#include <vector>
#include <netinet/in.h>
#include "DHCPReservation.h"

class DHCPReservationPool{
    struct in_addr startIp;
    struct in_addr endIp;
    std::vector<DHCPReservation> reservations;

    void createReservations();

    void decreaseLeease();

public:
    DHCPReservationPool(const char* startIpAddress, const char* endIpAddress);

    void startThreadPrinting();

    void startThreadDecreasing();

    void printReservations() const;

    const char* startNewReservation(const unsigned char* chaddr);
    
    const char* confirmReservation(const unsigned char* chaddr);
    
    const char* getIPaddr(const unsigned char* chaddr);

};

#endif // DHCPRESERVATION_H