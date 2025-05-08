/// @file firewall.hpp
/// @brief Defines structures and the Firewall class for packet inspection and filtering using Netfilter and Conntrack.

#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h> ///< For interacting with Netfilter queue in userspace (packet capturing and verdict setting)
#include <libnetfilter_conntrack/libnetfilter_conntrack.h> ///< For connection tracking handle
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h> ///< For TCP-specific conntrack attributes

#include <netinet/ip.h>      ///< For struct iphdr (parsing IPv4 packet headers)
#include <netinet/tcp.h>     ///< For struct tcphdr (parsing TCP packet headers)
#include <netinet/ether.h>   ///< For struct ether_header (parsing Ethernet frames)
#include <netinet/udp.h>     ///< For struct udphdr (parsing UDP packet headers)
#include <netinet/ip_icmp.h> ///< For struct icmphdr (parsing ICMP packet headers)
#include <linux/if_ether.h>  ///< For ETH_P_IP and other Ethernet constants
#include <linux/netfilter.h> ///< For Netfilter verdict constants (e.g., NF_ACCEPT, NF_DROP)
#include <thread>            ///< For std::thread
#include <cstring>           ///< For strerror

#include "aclManager.hpp"  ///< For ACLManager and ACE definitions

/// @struct tcpFullHdr
/// @brief Represents a full TCP packet including Ethernet, IP, and TCP headers.
/// @var tcpFullHdr::eth
/// Pointer to the Ethernet header.
/// @var tcpFullHdr::iph
/// Pointer to the IPv4 header.
/// @var tcpFullHdr::tcph
/// Pointer to the TCP header.
/// @var tcpFullHdr::isInbound
/// True if the packet is inbound; false if outbound.
struct tcpFullHdr {
    ether_header* eth;
    iphdr* iph;
    tcphdr* tcph;
    bool isInbound;
};

/// @struct udpFullHdr
/// @brief Represents a full UDP packet including Ethernet, IP, and UDP headers.
/// @var udpFullHdr::eth
/// Pointer to the Ethernet header.
/// @var udpFullHdr::iph
/// Pointer to the IPv4 header.
/// @var udpFullHdr::udph
/// Pointer to the UDP header.
/// @var udpFullHdr::isInbound
/// True if the packet is inbound; false if outbound.
struct udpFullHdr {
    ether_header* eth;
    iphdr* iph;
    udphdr* udph;
    bool isInbound;
};

/// @struct icmpFullHdr
/// @brief Represents a full ICMP packet including Ethernet, IP, and ICMP headers.
/// @var icmpFullHdr::eth
/// Pointer to the Ethernet header.
/// @var icmpFullHdr::iph
/// Pointer to the IPv4 header.
/// @var icmpFullHdr::icmph
/// Pointer to the ICMP header.
/// @var icmpFullHdr::isInbound
/// True if the packet is inbound; false if outbound.
struct icmpFullHdr {
    ether_header* eth;
    iphdr* iph;
    icmphdr* icmph;
    bool isInbound;
};

/// @struct Queue
/// @brief Holds handles and thread for processing a Netfilter queue.
/// @var Queue::h
/// Netfilter queue handle.
/// @var Queue::qh
/// Queue-specific handler.
/// @var Queue::ctHandle
/// Conntrack handle for connection state queries.
/// @var Queue::fd
/// File descriptor for receiving packets.
/// @var Queue::Thread
/// Worker thread processing the queue.
struct Queue {
    nfq_handle* h;
    nfq_q_handle* qh;
    nfct_handle* ctHandle;
    int fd;
    std::thread Thread;
};

/// @class Firewall
/// @brief Inspects packets from Netfilter queue and applies ACL rules via ACLManager.
class Firewall {
private:
    /// @brief Checks if an IP address belongs to a subnet.
    /// @param packetIp IP address from packet (network byte order).
    /// @param aceIp  IP address from ACE rule.
    /// @param subnetMask  Subnet mask.
    /// @return True if packetIp & subnetMask == aceIp & subnetMask.
    static bool isIpInSubnet(const uint32_t& packetIp, const uint32_t& aceIp, const uint32_t& subnetMask);

    /// @brief Verifies if ACE protocol matches packet protocol.
    static bool protocolMatches(const ACE& ace, Protocol protocol);

    /// @brief Checks if packet direction (inbound/outbound) matches ACE direction.
    static bool directionMatches(const ACE& ace, bool isInbound);

    /// @brief Matches packet source IP to ACE source.
    static bool sourceIpMatches(const ACE& ace, uint32_t& srcIp);

    /// @brief Matches packet destination IP to ACE destination.
    static bool destinationIpMatches(const ACE& ace, uint32_t& dstIp);

    /// @brief Matches packet destination port to ACE port rule.
    static bool portMatches(const ACE& ace, uint16_t& dstPort);

    /// @brief Validates established TCP connections via conntrack.
    static bool establishedCheck(const ACE& ace, uint8_t& tcpFlags, nfct_handle* h, uint8_t& proto,
                                 uint32_t& srcIp, uint32_t& desIp, uint16_t& srcPort, uint16_t& dstPort);

    /// @brief Checks if TCP flags match ACE flags rule.
    static bool tcpFlagsMatch(const ACE& ace, uint8_t& tcpFlags);

    /// @brief Processes Ethernet frame if needed (e.g., VLAN tags).
    static bool processEthernetFrame(const ether_header* eth);

    /// @brief Checks if ICMP type matches ACE port field.
    static bool icmpTypeMatch(const ACE& ace, uint8_t& type);

    /// @brief Logs packet decisions.
    static void LoggingPacket(uint32_t& srcIp, uint32_t& dstIp, uint16_t srcPort,
                              uint16_t dstPort, const std::string& protocol,
                              const std::string& action, const std::string& reason);

    /// @brief Queries conntrack table for an existing connection.
    static bool query(nfct_handle* h, uint8_t& proto, uint32_t& srcIp,
                      uint32_t& desIp, uint16_t& srcPort, uint16_t& dstPort);

    /// @brief Handles TCP packet ACL evaluation.
    /// @return True to allow, false to drop.
    static bool TCP(const tcpFullHdr* packet, Queue& q);

    /// @brief Handles UDP packet ACL evaluation.
    static bool UDP(const udpFullHdr* packet);

    /// @brief Handles ICMP packet ACL evaluation.
    static bool ICMP(const icmpFullHdr* packet);

protected:
    /// @brief Map of active queue workers indexed by queue number.
    static std::map<int, Queue> threadWorker;

    /// @brief Pointer to the ACL manager instance.
    static ACLManager* manager;

    /// @brief Sends a drop verdict to Netfilter for the packet.
    static bool dropPacket(nfq_q_handle* qh, uint32_t id);

    /// @brief Sends an accept verdict to Netfilter for the packet.
    static bool allowPacket(nfq_q_handle* qh, uint32_t id);

    /// @brief Callback invoked by libnetfilter_queue for each packet.
    static int callback(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfa, void* data);

    /// @brief Starts processing loop for a given queue number.
    static void start(int queueNumber);

public:
    /// @brief Constructs the Firewall, initializes Netfilter queues and threads.
    /// @param ACLmanager Reference to ACLManager providing ACE rules.
    Firewall(ACLManager& ACLmanager);

    /// @brief Cleans up threads and Netfilter handles on destruction.
    ~Firewall();
};
