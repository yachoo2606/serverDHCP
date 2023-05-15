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


#define SERVER_PORT 67
#define RESERVATION_SECONDS 3600

using namespace std;

struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    unsigned char chaddr[16];
    char sname[64];
    char file[128];
    uint32_t cookie;
    uint8_t options[308];
};

enum class Status{
    NONE,
    IN_PROCESS,
    RESERVED
};

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

class DHCPReservation{
    Status status;
    unsigned char chaddr[16];
    struct in_addr ip;
    std::chrono::seconds leeseInSeconds;
public:
    DHCPReservation(int seconds, unsigned char *address, Status status_,const char* ipAddress){
        leeseInSeconds = std::chrono::seconds(seconds);
        memcpy(&chaddr, address, sizeof(address));
        status = status_;
        inet_pton(AF_INET, ipAddress, &ip);
    }

    DHCPReservation(){
        leeseInSeconds = std::chrono::seconds(0);
        std::memset(&chaddr, 0, sizeof(chaddr));
        status = Status::NONE;
        std::memset(&ip, 0, sizeof(ip));
    }
    ~DHCPReservation(){

    }

    Status getStatus() const {
        return status;
    }

    void setStatus(Status newStatus) {
        status = newStatus;
    }

    const unsigned char* getChaddr() const {
        return chaddr;
    }

    void setChaddr(const unsigned char* address) {
        std::memcpy(chaddr, address, sizeof(chaddr));
    }

    std::chrono::seconds getLeaseInSeconds() const {
        return leeseInSeconds;
    }

    void setLeaseInSeconds(int seconds) {
        leeseInSeconds = std::chrono::seconds(seconds);
    }

    const char* getIpAddress_string() const {
        // Convert the IP address to a string and return it
        return inet_ntoa(ip);
    }

    struct in_addr getIpAddress() const {
        // Convert the IP address to a string and return it
        return ip;
    }

    void setIpAddress(const char* ipAddress) {
        // Set the IP address using the provided string
        inet_pton(AF_INET, ipAddress, &ip);
    }

    void print_mac_address() {
        printf("%02x:%02x:%02x:%02x:%02x:%02x ",
           chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    }
};


class DHCPReservationPool{
    struct in_addr startIp;
    struct in_addr endIp;
    std::vector<DHCPReservation> reservations;

    void createReservations() {
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

public:
    DHCPReservationPool(const char* startIpAddress, const char* endIpAddress){
        inet_pton(AF_INET, startIpAddress, &startIp);
        inet_pton(AF_INET, endIpAddress, &endIp);
        createReservations();
    }

    void printReservations() const {
        for (DHCPReservation reservation : reservations) {
            std::cout << "IP Address: " << reservation.getIpAddress_string() << ", ";
            std::cout << "Chaddr: ";
            reservation.print_mac_address();
            std::cout << " Status: " << reservation.getStatus();
            std::cout << " Leese: " << reservation.getLeaseInSeconds().count() <<std::endl;
        }
    }

    const char* startNewReservation(const unsigned char* chaddr) {
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
    
    const char* confirmReservation(const unsigned char* chaddr){
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
    
    const char* getIPaddr(const unsigned char* chaddr){
        for(auto &res: reservations){
            if(res.getStatus() != Status::NONE &&
                std::memcmp(res.getChaddr(), chaddr, sizeof(res.getChaddr())) == 0){
                    return res.getIpAddress_string();
            }
        }
        return "false";
    }


};

int socketSetup(char* interface_name){
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        std::cerr << "Failed to bind socket to interface " << interface_name << "\n";
        close(sock);
        return 1;
    }

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0) {
        std::cerr << "Failed to set socket option for broadcasting." << std::endl;
        return 1;
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT); // Listen on DHCP server port
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Failed to bind socket to port 67\n";
        close(sock);
        return 1;
    }

    return sock;
}

void print_mac_address(unsigned char *mac){
    printf("\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_dhcp_options(struct dhcp_packet packet) {
    uint8_t *options = packet.options;
    int option_code, option_len;

    while (*options != 0xff) {
        option_code = *options++;
        if (option_code == 0) {
            printf("\t\tPadding (%d bytes)\n", 1);
            continue;
        } else if (option_code == 255) {
            printf("\t\tEnd\n");
            break;
        }
        option_len = *options++;
        printf("\t\tOption %d: ", option_code);
        for (int i = 0; i < option_len; i++) {
            printf("%02x", options[i]);
            if (i != option_len - 1) printf(":");
        }
        printf("\n");
        options += option_len;
    }
}

void print_dhcp_packet(struct dhcp_packet packet) {
    printf("\top: %d\n", packet.op);
    printf("\thtype: %d\n", packet.htype);
    printf("\thlen: %d\n", packet.hlen);
    printf("\thops: %d\n", packet.hops);
    printf("\txid: %u\n", ntohl(packet.xid));
    printf("\tsecs: %d\n", ntohs(packet.secs));
    printf("\tflags: %d\n", ntohs(packet.flags));
    printf("\tciaddr: %s\n", inet_ntoa(packet.ciaddr));
    printf("\tyiaddr: %s\n", inet_ntoa(packet.yiaddr));
    printf("\tsiaddr: %s\n", inet_ntoa(packet.siaddr));
    printf("\tgiaddr: %s\n", inet_ntoa(packet.giaddr));
    print_mac_address(packet.chaddr);
    printf("\tsname: %s\n", packet.sname);
    printf("\tfile: %s\n", packet.file);
    printf("\tcookie: %u\n", ntohl(packet.cookie));
    print_dhcp_options(packet);
    printf("\n");
}

bool isDHCPDiscovery(const dhcp_packet* packet) {
    // DHCP message type option code
    const uint8_t DHCP_OPTION_MESSAGE_TYPE = 53;

    // Iterate through the DHCP options until the end of options marker is encountered
    int offset = 0;
    while (offset < sizeof(packet->options) && packet->options[offset] != 255) {
        // Check if the current option is the DHCP message type option
        if (packet->options[offset] == DHCP_OPTION_MESSAGE_TYPE) {
            // Get the length of the option data
            uint8_t optionLength = packet->options[offset + 1];

            // Check the option data value
            if (offset + optionLength + 2 < sizeof(packet->options)) {
                uint8_t messageType = packet->options[offset + 2];
                return messageType == 1;  // DHCPDISCOVER message type value
            }
        }

        // Move to the next option
        offset += packet->options[offset + 1] + 2;
    }

    // DHCP message type option not found, assuming it's not a DHCPDISCOVER packet
    return false;
}

bool isDHCPAck(const dhcp_packet* packet) {
    // DHCP message type option code
    const uint8_t DHCP_OPTION_MESSAGE_TYPE = 53;

    // Iterate through the DHCP options until the end of options marker is encountered
    int offset = 0;
    while (offset < sizeof(packet->options) && packet->options[offset] != 255) {
        // Check if the current option is the DHCP message type option
        if (packet->options[offset] == DHCP_OPTION_MESSAGE_TYPE) {
            // Get the length of the option data
            uint8_t optionLength = packet->options[offset + 1];

            // Check the option data value
            if (offset + optionLength + 2 < sizeof(packet->options)) {
                uint8_t messageType = packet->options[offset + 2];
                return messageType == 5;  // DHCPACK message type value
            }
        }

        // Move to the next option
        offset += packet->options[offset + 1] + 2;
    }

    // DHCP message type option not found, assuming it's not a DHCPACK packet
    return false;
}

bool isDHCPRequest(const dhcp_packet* packet) {
    // DHCP message type option code
    const uint8_t DHCP_OPTION_MESSAGE_TYPE = 53;

    // Iterate through the DHCP options until the end of options marker is encountered
    int offset = 0;
    while (offset < sizeof(packet->options) && packet->options[offset] != 255) {
        // Check if the current option is the DHCP message type option
        if (packet->options[offset] == DHCP_OPTION_MESSAGE_TYPE) {
            // Get the length of the option data
            uint8_t optionLength = packet->options[offset + 1];

            // Check the option data value
            if (offset + optionLength + 2 < sizeof(packet->options)) {
                uint8_t messageType = packet->options[offset + 2];
                return messageType == 3;  // DHCPREQUEST message type value
            }
        }

        // Move to the next option
        offset += packet->options[offset + 1] + 2;
    }

    // DHCP message type option not found, assuming it's not a DHCPREQUEST packet
    return false;
}

bool checkIfDHCP(dhcp_packet packet){
    if (packet.op != 1) { // Ignore non-DHCP packets
        std::cerr << "non DHCP packet\n";
        return false;
    }
    if (packet.htype!= 1) { // Ignore non-Ethernet packets
        std::cerr << "Received non ethernet packet\n";
        return false;
    }
    if (packet.hlen != 6) { // Ignore non-6-byte MAC addresses
        std::cerr << "Received non 6-bytes packet\n";
        return false;
    }
    if (memcmp(&packet.cookie, "\x63\x82\x53\x63", 4) != 0) { // Ignore non-DHCP messages
        std::cerr<<"cookie not equals dhcp"<<std::endl;
        return false;
    }
    if (packet.options[2] == 1) { // Ignore non-discovery messages
        std::cerr << "Received discovery packet\n";
        return true;
    }
    if (packet.options[2] != 3) { // Ignore non-discovery messages
        std::cerr << "Received request packet\n";
        return false;
    }
    return true;
}

void fill_offer_packet(dhcp_packet* packet, const dhcp_packet* request_packet, DHCPReservationPool &pool) {
    // Fill in the header fields of the DHCP offer packet
    packet->op = 2;
    packet->htype = 1;
    packet->hlen = 6;
    packet->hops = 0;
    packet->xid = request_packet->xid;
    packet->secs = 0;
    packet->flags = htons(0x8000);
    packet->ciaddr.s_addr = 0;
    // packet->yiaddr.s_addr = inet_addr("192.168.1.3"); // IP address offered to the client
    packet->yiaddr.s_addr = inet_addr(pool.startNewReservation(request_packet->chaddr)); // IP address offered to the client
    
    packet->siaddr.s_addr = inet_addr("192.168.1.2"); // IP address of the DHCP server
    packet->giaddr.s_addr = 0;
    memcpy(packet->chaddr, request_packet->chaddr, 6); // Copy the MAC address from the request packet
    memset(&packet->chaddr[6], 0, 10); // Fill the remaining bytes with zeros
    memset(packet->sname, 0, sizeof(packet->sname));
    memset(packet->file, 0, sizeof(packet->file));
    packet->cookie = htonl(0x63825363);

    // Fill in the DHCP options field of the offer packet
    int offset = 0;
    packet->options[offset++] = 53; // DHCP message type option
    packet->options[offset++] = 1;  // Length of the option data
    packet->options[offset++] = 2;  // DHCP offer message type

    packet->options[offset++] = 1;  // Subnet mask option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 255;
    packet->options[offset++] = 255;
    packet->options[offset++] = 255;
    packet->options[offset++] = 0;

    packet->options[offset++] = 3;  // Router option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 192;
    packet->options[offset++] = 168;
    packet->options[offset++] = 1;
    packet->options[offset++] = 1;

    packet->options[offset++] = 51; // IP address lease time option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 0;
    packet->options[offset++] = 0;
    packet->options[offset++] = 1;
    packet->options[offset++] = 1;  // Lease time in seconds

    packet->options[offset++] = 6; // IP address lease time option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 192;
    packet->options[offset++] = 160;
    packet->options[offset++] = 1;  // Lease time in seconds
    packet->options[offset++] = 1;

    packet->options[offset++] = 54; // DHCP server identifier option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 192;
    packet->options[offset++] = 168;
    packet->options[offset++] = 1;
    packet->options[offset++] = 2;

    packet->options[offset++] = 255; // End of options marker
}

void fill_ack_packet(dhcp_packet* packet, const dhcp_packet* request_packet, DHCPReservationPool &pool) {
    // Fill in the header fields of the DHCP ACK packet
    packet->op = 2;
    packet->htype = 1;
    packet->hlen = 6;
    packet->hops = 0;
    packet->xid = request_packet->xid;
    packet->secs = 0;
    packet->flags = htons(0x8000);
    packet->ciaddr.s_addr = 0;
    packet->yiaddr.s_addr = inet_addr(pool.confirmReservation(request_packet->chaddr)); // IP address assigned to the client
    packet->siaddr.s_addr = inet_addr("192.168.1.2"); // IP address of the DHCP server
    packet->giaddr.s_addr = 0;
    memcpy(packet->chaddr, request_packet->chaddr, 16); // Copy the MAC address from the request packet
    memset(packet->sname, 0, sizeof(packet->sname));
    memset(packet->file, 0, sizeof(packet->file));
    packet->cookie = htonl(0x63825363);

    // Fill in the DHCP options field of the ACK packet
    int offset = 0;
    packet->options[offset++] = 53; // DHCP message type option
    packet->options[offset++] = 1;  // Length of the option data
    packet->options[offset++] = 5;  // DHCP ACK message type

    packet->options[offset++] = 1;  // Subnet mask option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 255;
    packet->options[offset++] = 255;
    packet->options[offset++] = 255;
    packet->options[offset++] = 0;

    packet->options[offset++] = 3;  // Router option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 192;
    packet->options[offset++] = 168;
    packet->options[offset++] = 1;
    packet->options[offset++] = 1;

    packet->options[offset++] = 51;  // Subnet mask option
    packet->options[offset++] = 4;  // Length of the option data
    packet->options[offset++] = 0;
    packet->options[offset++] = 14;
    packet->options[offset++] = 1;
    packet->options[offset++] = 0;

    // Add other DHCP options as needed

    packet->options[offset++] = 255; // End of options marker
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[1] << " <interface>\n";
        return 1;
    }
    struct in_addr startIp;
    struct in_addr endIp;
    inet_pton(AF_INET, argv[2], &startIp);
    inet_pton(AF_INET, argv[3], &endIp);
    uint32_t startIpNetworkOrder = ntohl(startIp.s_addr);
    uint32_t endIpNetworkOrder = ntohl(endIp.s_addr);
    if(startIpNetworkOrder > endIpNetworkOrder){
        std::cerr << "Starting IP must be greater then ending IP"<<std::endl;
        return 1;
    }

    DHCPReservationPool pool(argv[2],argv[3]);
    pool.printReservations();
    int sock = socketSetup(argv[1]);

    dhcp_packet packet;
    ssize_t recv_size;
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    dhcp_packet dhcp_offer;
    while (true) {
        recv_size = recvfrom(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&client_address, &client_address_len);
        std::cout<<"Reciveed packet!"<<std::endl;
        if (recv_size < 0) {
            std::cerr << "Failed to receive DHCP packet\n";
            continue;
        }
        
        if(!checkIfDHCP(packet)) continue;
        
        print_dhcp_packet(packet);

        if(isDHCPDiscovery(&packet)){
            memset(&dhcp_offer,0,sizeof(dhcp_offer));
            fill_offer_packet(&dhcp_offer, &packet, pool);
            print_dhcp_packet(dhcp_offer);
        }

        if(isDHCPRequest(&packet)){
            memset(&dhcp_offer,0,sizeof(dhcp_offer));
            fill_ack_packet(&dhcp_offer,&packet, pool);
        }

        if(isDHCPAck(&packet)){

        }
        
        memset(&client_address,0,sizeof(client_address));
        client_address.sin_family = AF_INET;
        client_address.sin_port = htons(68);
        client_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        ssize_t sent_size = sendto(sock, &dhcp_offer, sizeof(dhcp_offer), 0, (struct sockaddr*)&client_address, sizeof(client_address));
        if(sent_size < 0){
            std::cerr << "Failed to send DHCP offer packet to ";
            print_mac_address(packet.chaddr);
            continue;
        }
        pool.printReservations();
        // print_mac_address(packet.chaddr);
    }
    
    close(sock);

    // DHCPReservationPool pool(argv[2],argv[3]);
    // pool.printReservations();

    // struct in_addr addr;

    // std::cout<<"\n\n";

    // inet_pton(AF_INET, "192.168.1.3", &(addr.s_addr));
    // pool.startNewReservation(addr);
    // inet_pton(AF_INET, "192.168.1.15", &(addr.s_addr));
    // pool.startNewReservation(addr);
    // inet_pton(AF_INET, "192.168.1.20", &(addr.s_addr));
    // pool.startNewReservation(addr);

    // pool.printReservations();

    return 0;
}

//on clinet test with 

// dhclient -4 -d

//cat /var/log/syslog | grep -Ei 'dhcp' //check logs for errors
//check gw:  ip route
