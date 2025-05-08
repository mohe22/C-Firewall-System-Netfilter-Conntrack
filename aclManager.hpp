#ifndef ACL_MANAGER_HPP
#define ACL_MANAGER_HPP

#include <iostream>
#include <cstdint>
#include <map>
#include <algorithm>
#include <sstream>
#include <vector>
#include <arpa/inet.h> // For inet_pton
#include <iomanip>     // for setw

using namespace std;

/**
 * @brief TCP flag bitmasks for packet filtering
 * 
 * These flags represent the various TCP control bits used in network packet filtering
 */
#define TCP_FIN 0x01 ///< Finish flag (used to terminate the connection)
#define TCP_SYN 0x02 ///< Synchronize flag (used to initiate a connection)
#define TCP_RST 0x04 ///< Reset flag (used to reset the connection)
#define TCP_PSH 0x08 ///< Push flag (used to push data to the receiving application)
#define TCP_ACK 0x10 ///< Acknowledgment flag (used to acknowledge receipt of data)
#define TCP_URG 0x20 ///< Urgent flag (used to indicate urgent data)
#define TCP_ECE 0x40 ///< ECN Echo flag (used for Explicit Congestion Notification)
#define TCP_CWR 0x80 ///< Congestion Window Reduced flag (used to indicate congestion control)

/**
 * @enum Verdict
 * @brief Action to be taken for matching packets
 */
enum Verdict {
    DENY,   ///< Block the packet
    PERMIT  ///< Allow the packet
};

/**
 * @enum Direction
 * @brief Network traffic direction for rule application
 */
enum Direction {
    Inbound,  ///< Incoming traffic to the protected network
    Outbound, ///< Outgoing traffic from the protected network
    Both      ///< Both incoming and outgoing traffic
};

/**
 * @enum Protocol
 * @brief Network protocols supported for filtering
 */
enum Protocol {
    TCP,  ///< Transmission Control Protocol
    UDP,  ///< User Datagram Protocol
    ICMP, ///< Internet Control Message Protocol
    All   ///< All IP protocols
};

/**
 * @enum PortOp
 * @brief Port comparison operators for rule matching
 */
enum PortOp {
    Eq,  ///< Equal to port number
    Neq, ///< Not equal to port number
    Gt,  ///< Greater than port number
    Lt   ///< Less than port number
};

/**
 * @struct ACE
 * @brief Access Control Entry defining a single firewall rule
 * 
 * Contains all parameters needed to match network traffic and specify actions
 */
struct ACE {
    int id;             ///< Unique identifier for the rule
    int priority;       ///< Rule priority (lower numbers evaluated first)
    Direction direction;///< Traffic direction to match
    Verdict action;     ///< Action to take (PERMIT/DENY)
    Protocol protocol;  ///< IP protocol to match

    uint32_t srcIp;     ///< Source IP address to match
    uint32_t srcMask;   ///< Source subnet mask

    uint32_t dstIp;     ///< Destination IP address to match
    uint32_t dstmask;   ///< Destination subnet mask

    int port;           ///< Port number to match (for TCP/UDP)

    PortOp portOp;      ///< Port comparison operator

    uint8_t icmpType = -1; ///< ICMP type to match (for ICMP protocol)
    uint8_t tcpFlags = -1; ///< TCP flags to match (for TCP protocol)

    bool established;   ///< Match established TCP connections
};

/**
 * @class ACLManager
 * @brief Manages Access Control Entries (ACEs) in a Network Firewall.
 * 
 * Provides functionality to add, remove, update, and display firewall rules,
 * as well as convert between various network representations and formats.
 */
class ACLManager {
public:
    vector<ACE> ACEs; ///< Collection of all Access Control Entries

    /**
     * @brief Add a new Access Control Entry to the list
     * @param ace The ACE to add
     * @return true if successful, false otherwise
     */
    bool addACE(const ACE &ace);
    
    /**
     * @brief Remove an Access Control Entry by ID
     * @param id The ID of the ACE to remove
     * @return true if found and removed, false otherwise
     */
    bool deleteACE(int &id);
    
    /**
     * @brief Update an existing Access Control Entry
     * @param id The ID of the ACE to update
     * @param ace The new ACE data
     * @return true if found and updated, false otherwise
     */
    bool updateACE(int &id, const ACE &ace);
    
    /**
     * @brief Print all Access Control Entries in a formatted table
     */
    void printACEs();
    
    /**
     * @brief Print details of a single Access Control Entry
     * @param a The ACE to print
     */
    void printACE(const ACE &a);

 
    /**
     * @brief Check if source port matches ACE conditions
     * @param ACE The rule to check against
     * @param srcPort The source port to test
     * @return true if port matches rule conditions, false otherwise
     */
    bool portSrcMatches(const ACE &ACE, uint16_t &srcPort);

    // New methods
    
    /**
     * @brief Parse a text line into an ACE structure
     * @param line The input text line containing rule definition
     * @return The parsed ACE structure
     * @throws invalid_argument if parsing fails
     */
    ACE parseACE(const string &line);

    /**
     * @brief Convert CIDR notation to subnet mask
     * @param cidr The CIDR value (0-32)
     * @return The subnet mask in network byte order
     * @throws invalid_argument if CIDR is invalid
     */
    static uint32_t cidrToMask(int cidr);
    
    /**
     * @brief Parse an IP address string to 32-bit value
     * @param input The IP address string (e.g., "192.168.1.1")
     * @return The IP address in network byte order
     * @throws invalid_argument if IP is invalid
     */
    static uint32_t parseIp(const string &input);
    
    /**
     * @brief Parse a subnet mask string to 32-bit value
     * @param input The mask string (e.g., "255.255.255.0" or "/24")
     * @return The subnet mask in network byte order
     * @throws invalid_argument if mask is invalid
     */
    static uint32_t parseMask(const string &input);
    
    /**
     * @brief Convert direction string to Direction enum
     * @param s The direction string
     * @return Corresponding Direction enum value
     * @throws invalid_argument if string is invalid
     */
    static Direction fromDir(const string &s);
    
    /**
     * @brief Convert protocol string to Protocol enum
     * @param s The protocol string
     * @return Corresponding Protocol enum value
     * @throws invalid_argument if string is invalid
     */
    static Protocol fromProto(const string &s);
    
    /**
     * @brief Convert action string to Verdict enum
     * @param s The action string
     * @return Corresponding Verdict enum value
     * @throws invalid_argument if string is invalid
     */
    static Verdict fromVerdict(const string &s);
    
    /**
     * @brief Convert port operator string to PortOp enum
     * @param s The operator string
     * @return Corresponding PortOp enum value
     * @throws invalid_argument if string is invalid
     */
    static PortOp fromPortOp(const string &s);
    
    /**
     * @brief Split a string by delimiter
     * @param s The string to split
     * @param d The delimiter character
     * @return Vector of string tokens
     */
    static vector<string> split(const string &s, char d);

    // Conversion methods for display purposes
    
    /**
     * @brief Convert Protocol enum to string
     * @param protocol The protocol enum value
     * @return String representation of protocol
     */
    static string fromEnumToStringProtocol(const Protocol &protocol);
    
    /**
     * @brief Convert PortOp enum to string
     * @param portOp The port operator enum value
     * @return String representation of operator
     */
    static string fromEnumToStringPortOp(const PortOp &portOp);
    
    /**
     * @brief Convert 32-bit IP address to string
     * @param ip The IP address in network byte order
     * @return Dotted-decimal IP string
     */
    static string ipToStr(uint32_t ip);
    
    /**
     * @brief Convert subnet mask to string representation
     * @param m The subnet mask in network byte order
     * @return String representation (either dotted-decimal or CIDR)
     */
    static string maskToStr(const uint32_t &m);
    
    /**
     * @brief Convert TCP flags bitmap to string
     * @param flags The TCP flags bitmap
     * @return Slash-separated string of flag names
     */
    static string tcpFlagsToString(const uint8_t &flags);
    
    /**
     * @brief Convert ICMP type to descriptive string
     * @param type The ICMP type number
     * @return Descriptive ICMP type name
     */
    static string icmpTypeToString(const uint8_t &type);
    
    /**
     * @brief Convert Verdict enum to string
     * @param verdict The action enum value
     * @return String representation ("PERMIT" or "DENY")
     */
    static string fromEnumToStringVerdict(Verdict verdict);
    
    /**
     * @brief Convert Direction enum to string
     * @param direction The direction enum value
     * @return String representation ("Inbound", "Outbound", or "Both")
     */
    static string fromEnumToStringDirection(Direction direction);
};

#endif