#include "firewall.hpp"
#include "log.hpp"

map<int, Queue> Firewall::threadWorker;
ACLManager *Firewall::manager = nullptr;
void Firewall::LoggingPacket(uint32_t &srcIp, uint32_t &dstIp, uint16_t srcPort, uint16_t dstPort, const string &protocol, const string &action, const string &reason)
{
	Logger::app_logger->warn(
		"[{}] {} packet {}:{} -> {}:{} -- reason: {}",
		action,	  // "DROP" or "ALLOW"
		protocol, // "TCP", "UDP", "ICMP"
		manager->ipToStr(srcIp), srcPort,
		manager->ipToStr(dstIp), dstPort,
		reason // e.g. "No matching ACE" or "Flag mismatch"
	);
}

Firewall::Firewall(ACLManager &ACLmanager)
{
	manager = &ACLmanager;

	for (size_t i = 0; i < 4; i++)
	{
		nfq_handle *h = nfq_open();
		if (!h)
		{
			perror("nfq_open failed");
			exit(1);
		}
		nfct_handle *ctHandle = nfct_open(CONNTRACK, 0);
		if (!ctHandle)
		{
			perror("nfct_open faild");
			exit(1);
		}

		if (nfq_unbind_pf(h, AF_INET) < 0)
		{
			perror("nfq_unbind_pf failed");
			exit(1);
		}

		if (nfq_bind_pf(h, AF_INET) < 0)
		{
			perror("nfq_bind_pf failed");
			exit(1);
		}

		int buff = 999999;
		nfnl_rcvbufsiz(nfq_nfnlh(h), buff);
		if (nfnl_rcvbufsiz(nfq_nfnlh(h), buff) < 0)
		{
			perror("nfnl_rcvbufsiz failed");
			exit(1);
		}

		int fd = nfq_fd(h);

		int value = 1;
		if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &value, sizeof(value)) < 0)
		{
			perror("setsockopt failed");
			exit(1);
		}
		nfq_q_handle *qh = nfq_create_queue(h, i, &Firewall::callback, reinterpret_cast<void *>(i));

		if (!qh)
		{
			perror("createQueue failed");
			exit(1);
		}

		if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		{
			perror("nfq_set_mode failed");
		}

		Queue q;

		q.fd = fd;
		q.h = h;
		q.qh = qh;
		q.ctHandle = ctHandle;
		q.Thread = thread([this, i]()
						  { this->start(i); });
		threadWorker[i] = move(q);
	}
}

void Firewall::start(int queueNumber)
{
	Queue &w = threadWorker[queueNumber];
	char buf[8192];

	while (true)
	{
		int rv = recv(w.fd, buf, sizeof(buf), 0);
		if (rv < 0)
		{
			perror("recv failed");
			break;
		}

		nfq_handle_packet(w.h, buf, rv);
	}
}

Firewall::~Firewall()
{
	for (auto &[_, q] : threadWorker)
	{
		q.Thread.join();
		nfq_destroy_queue(q.qh);
		nfq_close(q.h);
		nfct_close(q.ctHandle);
	}
}

bool Firewall::dropPacket(nfq_q_handle *qh, uint32_t id)
{
	int result = nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);

	if (result < 0)
	{

		return false;
	}

	return true;
}

bool Firewall::allowPacket(nfq_q_handle *qh, uint32_t id)
{
	int result = nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

	if (result < 0)
	{

		return false;
	}

	return true;
}
bool Firewall::query(nfct_handle *h, uint8_t &proto, uint32_t &srcIp, uint32_t &desIp, uint16_t &srcPort, uint16_t &dstPort)
{
	struct nf_conntrack *obj = nfct_new();
	if (!obj)
		return false;
	nfct_set_attr_u8(obj, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u32(obj, ATTR_IPV4_SRC, srcIp);
	nfct_set_attr_u32(obj, ATTR_IPV4_DST, desIp);
	nfct_set_attr_u8(obj, ATTR_L4PROTO, proto);
	nfct_set_attr_u16(obj, ATTR_PORT_SRC, srcPort);
	nfct_set_attr_u16(obj, ATTR_PORT_DST, dstPort);

	int res = nfct_query(h, NFCT_Q_GET, obj);
	if (res < 0)
	{
		if (errno == ENOENT)
		{
			return false;
		}
		else
		{
			return false;
		}
	}
	nfct_destroy(obj);
	return true;
}
int Firewall::callback(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa, void *data)
{



	unsigned char *packetData = nullptr;
	nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	int packetId = ntohl(ph->packet_id);
	int payloadLen = nfq_get_payload(nfa, &packetData);
	int queueIndex = static_cast<int>(reinterpret_cast<intptr_t>(data));
	Queue &queue = threadWorker[queueIndex];


	struct iphdr *iph = reinterpret_cast<iphdr *>(packetData);
	struct ether_header *eth = reinterpret_cast<ether_header *>(packetData);

	

	bool isInbound = (ph && (ph->hook == NF_INET_PRE_ROUTING || ph->hook == NF_INET_LOCAL_IN));
	int verdict = -1;

	switch (iph->protocol)
	{
	case IPPROTO_TCP:
	{
		auto *tcph = reinterpret_cast<tcphdr *>(packetData + iph->ihl * 4);

		tcpFullHdr tcp = {eth, iph, tcph, isInbound};
		verdict = TCP(&tcp, queue) ? allowPacket(qh, packetId) : dropPacket(qh, packetId);
		break;
	}

	case IPPROTO_UDP:
	{
		auto *udph = reinterpret_cast<udphdr *>(packetData + iph->ihl * 4);
		udpFullHdr udp = {eth, iph, udph, isInbound};
		verdict = UDP(&udp) ? allowPacket(qh, packetId) : dropPacket(qh, packetId);
		break;
	}

	case IPPROTO_ICMP:
	{
		auto *icmph = reinterpret_cast<icmphdr *>(packetData + iph->ihl * 4);
		icmpFullHdr icmp = {eth, iph, icmph, isInbound};
		verdict = ICMP(&icmp) ? allowPacket(qh, packetId) : dropPacket(qh, packetId);
		break;
	}

	default:
		verdict = dropPacket(qh, packetId);
		break;
	}

	return verdict;
}

bool Firewall::isIpInSubnet(const uint32_t &packetIp, const uint32_t &aceIp, const uint32_t &subnetMask)
{
	return (packetIp & subnetMask) == (aceIp & subnetMask);
}
bool Firewall::protocolMatches(const ACE &ACE, Protocol protocol)
{
	return ACE.protocol == Protocol::All || ACE.protocol == protocol;
}

bool Firewall::directionMatches(const ACE &ACE, bool isInbound)
{
	return ACE.direction == Direction::Both ||
		   (isInbound && ACE.direction == Direction::Inbound) ||
		   (!isInbound && ACE.direction == Direction::Outbound);
}

bool Firewall::sourceIpMatches(const ACE &ACE, uint32_t &srcIp)
{

	return isIpInSubnet(srcIp, ACE.srcIp, ACE.srcMask);
}

bool Firewall::destinationIpMatches(const ACE &ACE, uint32_t &dstIp)
{

	return isIpInSubnet(dstIp, ACE.dstIp, ACE.dstmask);
}

bool Firewall::portMatches(const ACE &ACE, uint16_t &dstPort)
{

	if (ACE.port == 0)
	{
		return true;
	}

	bool portMatch = false;
	if (ACE.portOp == PortOp::Eq)
	{
		portMatch = (dstPort == ACE.port);
	}
	else if (ACE.portOp == PortOp::Gt)
	{

		portMatch = (dstPort > ACE.port);
	}
	else if (ACE.portOp == PortOp::Lt)
	{
		portMatch = (dstPort < ACE.port);
	}
	else if (ACE.portOp == PortOp::Neq)
	{
		portMatch = (dstPort != ACE.port);
	}

	return portMatch;
}

bool Firewall::establishedCheck(const ACE &ACE, uint8_t &tcpFlags, nfct_handle *h,
								uint8_t &proto, uint32_t &srcIp, uint32_t &dstIp,
								uint16_t &srcPort, uint16_t &dstPort)
{

	if (!ACE.established)
	{
		return true;
	}

	if (tcpFlags & (TH_ACK | TH_RST))
	{
		if (query(h, proto, srcIp, dstIp, srcPort, dstPort))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return true;
	}
}

bool Firewall::tcpFlagsMatch(const ACE &ACE, uint8_t &tcpFlags)
{
	if (ACE.tcpFlags == 0)
	{
		return true;
	}

	bool exactMatch = (tcpFlags == ACE.tcpFlags);

	return exactMatch;
}

bool Firewall::TCP(const tcpFullHdr *packet, Queue &q)
{
	uint32_t srcIp = htonl(packet->iph->saddr);
	uint32_t dstIp = htonl(packet->iph->daddr);
	uint16_t dstPort = ntohs(packet->tcph->th_dport);
	uint16_t srcPort = ntohs(packet->tcph->th_sport);
	bool isInbound = packet->isInbound;
	uint8_t flags = packet->tcph->th_flags;
	string reason = "No matching ACE";
	for (const auto &ace : manager->ACEs)
	{
		if (!protocolMatches(ace, Protocol::TCP) || !directionMatches(ace, isInbound))
		{
			continue;
		}

		// Check if source IP matches
		if (!sourceIpMatches(ace, srcIp))
		{
			reason += "IP source mismatch packet src: " + manager->ipToStr(srcIp) +
					  " , ACE src: " + manager->ipToStr(ace.srcIp) +
					  " /" + manager->maskToStr(ace.srcMask) + "\n";
			continue;
		}

		// Check if destination IP matches
		if (!destinationIpMatches(ace, dstIp))
		{
			reason += "IP Destination mismatch packet dst: " + manager->ipToStr(dstIp) +
					  " , ACE dst: " + manager->ipToStr(ace.dstIp) +
					  " /" + manager->maskToStr(ace.dstmask) + "\n";
			continue;
		}

		// Check if destination port matches
		if (!portMatches(ace, dstPort))
		{
			reason += "Port Destination mismatch packet Port: " + to_string(dstPort) +
					  " , ACE port: " + to_string(ace.port) +
					  ", Packet Direction: " + (isInbound ? "Inbound" : "Outbound") + "\n";
			continue;
		}

		if (!establishedCheck(ace, flags, q.ctHandle, packet->iph->protocol, packet->iph->saddr, packet->iph->daddr, packet->tcph->th_sport, packet->tcph->th_dport))
		{
			reason += "Established check failed (invalid ACK/RST was sent)\n";
			continue;
		}

		// Check if TCP flags match
		if (!tcpFlagsMatch(ace, flags))
		{
			reason += "TCP flags mismatch Packet TCP flags: " + manager->tcpFlagsToString(flags) +
					  " ACE: " + manager->tcpFlagsToString(ace.tcpFlags) + "\n";
			continue;
		}

		if (ace.action == Verdict::DENY)
		{
			LoggingPacket(srcIp, dstIp, srcPort, dstPort, "TCP", "Dropped", reason);
			return false;
		}

		return true;
	}

	LoggingPacket(srcIp, dstIp, srcPort, dstPort, "TCP", "Dropped", reason);
	return false;
}

bool Firewall::UDP(const udpFullHdr *packet)
{
	uint32_t srcIp = htonl(packet->iph->saddr);
	uint32_t dstIp = htonl(packet->iph->daddr);
	uint16_t dstPort = ntohs(packet->udph->uh_dport);
	uint16_t srcPort = ntohs(packet->udph->uh_sport);
	bool isInbound = packet->isInbound;
	string reason = "No matching ACE";

	for (const auto &ace : manager->ACEs)
	{

		if (!protocolMatches(ace, Protocol::UDP))
		{
			continue;
		}
		if (!directionMatches(ace, isInbound))
		{
			reason += "Direction mismatch (packet is " + string(isInbound ? "Inbound" : "Outbound") +
					  ", ACE expects " + (ace.direction == Direction::Inbound ? "Inbound" : "Outbound") + "\n";
			continue;
		}
		if (!sourceIpMatches(ace, srcIp))
		{
			reason += "Source IP mismatch (packet src: " + manager->ipToStr(srcIp) +
					  ", ACE src: " + manager->ipToStr(ace.srcIp) +
					  "/" + manager->maskToStr(ace.srcMask) + "\n";
			continue;
		}
		if (!destinationIpMatches(ace, dstIp))
		{
			reason += "Destination IP mismatch (packet dst: " + manager->ipToStr(dstIp) +
					  ", ACE dst: " + manager->ipToStr(ace.dstIp) +
					  "/" + manager->maskToStr(ace.dstmask) + "\n";
			continue;
		}
		if (!portMatches(ace, dstPort))
		{
			reason += "Destination port mismatch (packet port: " + to_string(dstPort) +
					  ", ACE port: " + to_string(ace.port) + ")\n";
			continue;
		}

		if (ace.action == Verdict::DENY)
		{
			LoggingPacket(srcIp, dstIp, srcPort, dstPort, "UDP", "Dropped", reason);
			return false;
		}
		return true;
	}

	LoggingPacket(srcIp, dstIp, srcPort, dstPort, "UDP", "Dropped", reason);
	return false;
}

bool Firewall::ICMP(const icmpFullHdr *packet)
{
	uint32_t srcIp = htonl(packet->iph->saddr);
	uint32_t dstIp = htonl(packet->iph->daddr);
	uint8_t icmpType = packet->icmph->type;
	bool isInbound = packet->isInbound;
	string reason = "No matching ACE";

	for (const auto &ace : manager->ACEs)
	{

		if (!protocolMatches(ace, Protocol::ICMP))
		{
			reason += "Protocol mismatch (expected ICMP)\n";
			continue;
		}
		if (!directionMatches(ace, isInbound))
		{
			reason += "Direction mismatch (packet is " + string(isInbound ? "Inbound" : "Outbound") +
					  ", ACE expects " + (ace.direction == Direction::Inbound ? "Inbound" : "Outbound") + "\n";
			continue;
		}
		if (!sourceIpMatches(ace, srcIp))
		{
			reason += "Source IP mismatch (packet src: " + manager->ipToStr(srcIp) +
					  ", ACE src: " + manager->ipToStr(ace.srcIp) +
					  "/" + manager->maskToStr(ace.srcMask) + "\n";
			continue;
		}
		if (!destinationIpMatches(ace, dstIp))
		{
			reason += "Destination IP mismatch (packet dst: " + manager->ipToStr(dstIp) +
					  ", ACE dst: " + manager->ipToStr(ace.dstIp) +
					  "/" + manager->maskToStr(ace.dstmask) + "\n";
			continue;
		}
		if (ace.port != 0 && ace.port != icmpType)
		{
			reason += "ICMP type mismatch (packet type: " + to_string(icmpType) +
					  ", ACE type: " + to_string(ace.port) + ")\n";
			continue;
		}

		if (ace.action == Verdict::DENY)
		{
			LoggingPacket(srcIp, dstIp, 0, 0, "ICMP", "Dropped", reason);
			return false;
		}
		return true;
	}

	LoggingPacket(srcIp, dstIp, 0, 0, "ICMP", "Dropped", reason);
	return false;
}