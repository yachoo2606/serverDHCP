
#include "DHCPReservation.h"
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


DHCPReservation::DHCPReservation(int seconds, unsigned char *address, Status status_,const char* ipAddress){
    leeseInSeconds = std::chrono::seconds(seconds);
    memcpy(&chaddr, address, sizeof(address));
    status = status_;
    inet_pton(AF_INET, ipAddress, &ip);
}

DHCPReservation::DHCPReservation(){
    leeseInSeconds = std::chrono::seconds(0);
     std::memset(&chaddr, 0, sizeof(chaddr));
     status = Status::NONE;
     std::memset(&ip, 0, sizeof(ip));
}
DHCPReservation::~DHCPReservation(){

}

Status  DHCPReservation::getStatus() const {
    return status;
}

void DHCPReservation:: setStatus(Status newStatus) {
    status = newStatus;
}

const unsigned char* DHCPReservation:: getChaddr() const {
    return chaddr;
}

void DHCPReservation::setChaddr(const unsigned char* address) {
    std::memcpy(chaddr, address, sizeof(chaddr));
}

std::chrono::seconds DHCPReservation::getLeaseInSeconds(){
    return leeseInSeconds;
}

void DHCPReservation::setLeaseInSeconds(int seconds) {
    leeseInSeconds = std::chrono::seconds(seconds);
}

const char* DHCPReservation::getIpAddress_string() const {
    // Convert the IP address to a string and return it
    return inet_ntoa(ip);
}

struct in_addr DHCPReservation::getIpAddress() const {
    // Convert the IP address to a string and return it
    return ip;
}

void DHCPReservation::setIpAddress(const char* ipAddress) {
    // Set the IP address using the provided string
   inet_pton(AF_INET, ipAddress, &ip);
}

void DHCPReservation::print_mac_address() {
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
       chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
}

void DHCPReservation::decreseLeese(){
    if(this->status == Status::RESERVED){
        if(this->leeseInSeconds.count() > 0){
            this->leeseInSeconds--;
            if(this->leeseInSeconds.count() == 0){
                this->status = Status::NONE;
            }
        }
    }
}