#include "DHCPReservation.h"
#include "DHCPReservationPool.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <chrono>
#include <vector>
#include <string>
#include <thread>

#define RESERVATION_SECONDS 3600

std::ostream& operator<<(std::ostream& os, const Status& status) {
    switch (status) {
        case Status::NONE:
            os << "NONE";
            break;
        case Status::IN_PROCESS:
            os << "IN_PROCESS";
            break;
        case Status::RESERVED:
            os << "RESERVED";
    }
    return os;
}

void DHCPReservationPool::createReservations() {
    uint32_t startIpNetworkOrder = ntohl(startIp.s_addr);
    uint32_t endIpNetworkOrder = ntohl(endIp.s_addr);
    unsigned char zeroChaddr[16] = {0};
    for (uint32_t currentIpNetworkOrder = startIpNetworkOrder;
        currentIpNetworkOrder <= endIpNetworkOrder; ++currentIpNetworkOrder)
        {   
            struct in_addr currentIp;
            currentIp.s_addr = htonl(currentIpNetworkOrder);
            DHCPReservation reservation(0,zeroChaddr,Status::NONE,inet_ntoa(currentIp));
            reservations.push_back(reservation);
        }
    }

void DHCPReservationPool::decreaseLeease(){
    while(true){
        for(auto& reservation:reservations){
            reservation.decreseLeese();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

DHCPReservationPool::DHCPReservationPool(const char* startIpAddress, const char* endIpAddress){
    inet_pton(AF_INET, startIpAddress, &startIp);
    inet_pton(AF_INET, endIpAddress, &endIp);
    createReservations();
}

void DHCPReservationPool::startThreadPrinting(){
    std::thread printing(&DHCPReservationPool::printReservations, this);
    printing.detach();
        
}

void DHCPReservationPool::startThreadDecreasing(){
    std::thread decreasing(&DHCPReservationPool::decreaseLeease,this);
    decreasing.detach();
}

void DHCPReservationPool::printReservations() const {
    while(true){
        std::system("clear");
        for (DHCPReservation reservation : reservations) {
            std::cout << "IP Address: " << reservation.getIpAddress_string() << ", ";
            std::cout << "Chaddr: ";
            reservation.print_mac_address();
            std::cout << " Status: " << reservation.getStatus();
            std::cout << " Leese: " << reservation.getLeaseInSeconds().count() <<std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::system("clear");
    }
}

const char* DHCPReservationPool::startNewReservation(const unsigned char* chaddr) {
    for (auto& res : reservations) {
        if (res.getStatus() == Status::NONE) {
            res.setStatus(Status::IN_PROCESS);
            res.setChaddr(chaddr);
            res.setLeaseInSeconds(RESERVATION_SECONDS);
            return res.getIpAddress_string();
        } else if (res.getStatus() == Status::IN_PROCESS && std::memcmp(res.getChaddr(), chaddr, sizeof(res.getChaddr())) == 0) {
            // The MAC address is already assigned to an IP address
            return "false";
        }
    }
    return "false"; // No available reservations
}
    
const char* DHCPReservationPool::confirmReservation(const unsigned char* chaddr){
    for(auto& res: reservations){
        if((res.getStatus() == Status::IN_PROCESS || res.getStatus() == Status::RESERVED) &&
            std::memcmp(res.getChaddr(), chaddr, sizeof(res.getChaddr())) == 0){
                res.setStatus(Status::RESERVED);
                res.setLeaseInSeconds(RESERVATION_SECONDS);
                return res.getIpAddress_string();
        }
    }
    return "false";
}
    
const char* DHCPReservationPool::getIPaddr(const unsigned char* chaddr){
    for(auto &res: reservations){
        if(res.getStatus() != Status::NONE &&
            std::memcmp(res.getChaddr(), chaddr, sizeof(res.getChaddr())) == 0){
                return res.getIpAddress_string();
        }
    }
    return "false";
}