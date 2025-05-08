#include "aclManager.hpp"


bool ACLManager::addACE(const ACE& ace) {
	auto it = ACEs.begin();
	while (it != ACEs.end() && it->priority <= ace.priority) {
		++it;
	}
	
	ACEs.insert(it, ace);
	return true;
}

bool ACLManager::deleteACE(int& id) {
	for (auto it = ACEs.begin(); it != ACEs.end(); ++it) {
		if (it->id == id) {
			ACEs.erase(it);
			return true;
		}
	}
	return false;
}

bool ACLManager::updateACE(int& id, const ACE& ace) {
	for (auto& existingACE : ACEs) {
		if (existingACE.id == id) {
			existingACE = ace;
			return true;
		}
	}
	return false;
}
string ACLManager::fromEnumToStringVerdict(Verdict verdict){
	switch (verdict) {
		case DENY:   return "DENY";
		case PERMIT: return "PERMIT";
		default:     return "UNKNOWN";
	}
}
string ACLManager::fromEnumToStringDirection(Direction direction) {
	switch (direction) {
		case Inbound:   return "Inbound";
		case Outbound: return "Outbound";
		case Both:      return "Both";
		default:       return "UNKNOWN";
	}
}
string ACLManager::fromEnumToStringProtocol(const Protocol& protocol) {
	switch (protocol) {
		case TCP:  return "TCP";
		case UDP:  return "UDP";
		case ICMP: return "ICMP";
		case All:  return "All";
		default:   return "UNKNOWN_PROTOCOL";
	}
}
string ACLManager::fromEnumToStringPortOp(const PortOp &portOp) {
	switch (portOp) {
		case Eq:  return "Eq";
		case Neq: return "Neq";
		case Gt:  return "Gt";
		case Lt:  return "Lt";
		default:  return "UNKNOWN_PORT_OP";
	}
}
void ACLManager::printACEs() {
	if (ACEs.empty()) {
		cout << "\n\033[1;36mNo ACL rules configured.\033[0m\n";
		return;
	}

	cout << "\n\033[1;36mNFWall Access Control List\033[0m\n";
	cout << "\033[1;37m┌───────────────────────────────────────────────────────────────────────────────────────────────┐\033[0m\n";

	for (const auto& ace : ACEs) {
		// Prepare values
		string dir = fromEnumToStringDirection(ace.direction);
		string action = fromEnumToStringVerdict(ace.action);
		string protoStr = fromEnumToStringProtocol(ace.protocol);
		
		string src = (ace.srcIp == 0 && ace.srcMask == 0)
			? "any"
			: (ace.srcMask == 0xFFFFFFFF)
				? "host " + ipToStr(ace.srcIp)
				: ipToStr(ace.srcIp) + "/" + to_string(__builtin_popcount(ace.srcMask));

		string dst = (ace.dstIp == 0 && ace.dstmask == 0)
			? "any"
			: (ace.dstmask == 0xFFFFFFFF)
				? "host " + ipToStr(ace.dstIp)
				: ipToStr(ace.dstIp) + "/" + to_string(__builtin_popcount(ace.dstmask));

		string port_type;
		if (ace.protocol == TCP || ace.protocol == UDP) {
			port_type = fromEnumToStringPortOp(ace.portOp) + " " + to_string(ace.port);
		} else if (ace.protocol == ICMP) {
			port_type =icmpTypeToString(ace.icmpType);
		} else {
			port_type = "-";
		}

		string flags = (ace.protocol == TCP) ? tcpFlagsToString(ace.tcpFlags) : "-";
		string established = ace.established ? "Yes" : "No";

		// Print ACE details in a table-like format
		cout << "\033[1;37m│ \033[1;33mID:\033[0m " << setw(6) << left << ace.id 
			 << " \033[1;33mPriority:\033[0m " << setw(4) << left << ace.priority
			 << " \033[1;33mAction:\033[0m ";
		
		// Color code the action
		if (action == "PERMIT") {
			cout << "\033[1;32m" << setw(7) << left << action << "\033[0m";
		} else {
			cout << "\033[1;31m" << setw(7) << left << action << "\033[0m";
		}
		
		cout << " \033[1;33mDir:\033[0m " << setw(8) << left << dir
			 << " \033[1;33mProto:\033[0m " << setw(5) << left << protoStr << "\033[1;37m│\033[0m\n";
		
		cout << "\033[1;37m│ \033[1;33mSource:\033[0m " << setw(24) << left << src 
			 << " \033[1;33mDestination:\033[0m " << setw(24) << left << dst
			 << " \033[1;33mPort/Type:\033[0m " << setw(12) << left << port_type << "\033[1;37m│\033[0m\n";
		
		if (ace.protocol == TCP) {
			cout << "\033[1;37m│ \033[1;33mTCP Flags:\033[0m " << setw(20) << left << flags
				 << " \033[1;33mEstablished:\033[0m " << setw(8) << left << established
				 << " " << string(32, ' ') << "\033[1;37m│\033[0m\n";
		}
		
		cout << "\033[1;37m├───────────────────────────────────────────────────────────────────────────────────────────────┤\033[0m\n";
	}
	cout << "\033[1;37m└───────────────────────────────────────────────────────────────────────────────────────────────┘\033[0m\n";
}





uint32_t ACLManager::cidrToMask(int cidr) {
	if (cidr < 0 || cidr > 32) throw invalid_argument("Invalid CIDR");
	return (cidr == 0) ? 0 : ~((1U << (32 - cidr)) - 1);
}

uint32_t ACLManager::parseIp(const string &input) {
	if (input == "any") return 0;
	string s = input;
	if (s.rfind("host ", 0) == 0) s = s.substr(5);
	size_t slash = s.find('/');
	if (slash != string::npos) s = s.substr(0, slash);

	struct in_addr addr;
	if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
		throw invalid_argument("Invalid IP: " + s);
	return ntohl(addr.s_addr);
}

uint32_t ACLManager::parseMask(const string &input) {
	if (input == "any") return 0;
	if (input == "host" || input.rfind("host ", 0) == 0) return 0xFFFFFFFF;

	size_t slash = input.find('/');
	if (slash != string::npos) {
		string part = input.substr(slash + 1);
		if (all_of(part.begin(), part.end(), ::isdigit))
			return cidrToMask(stoi(part));

		struct in_addr addr;
		if (inet_pton(AF_INET, part.c_str(), &addr) == 1) {
			uint32_t m = ntohl(addr.s_addr), inv = ~m;
			if ((inv & (inv + 1)) != 0)
				throw invalid_argument("Non-contiguous mask: " + part);
			return m;
		}
	}

	struct in_addr addr;
	if (inet_pton(AF_INET, input.c_str(), &addr) == 1) {
		uint32_t m = ntohl(addr.s_addr), inv = ~m;
		if ((inv & (inv + 1)) != 0)
			throw invalid_argument("Non-contiguous mask: " + input);
		return m;
	}

	if (all_of(input.begin(), input.end(), ::isdigit))
		return cidrToMask(stoi(input));

	throw invalid_argument("Invalid mask: " + input);
}

Direction ACLManager::fromDir(const string& s) {
	if (s=="Inbound"||s=="inbound"||s=="in") return Inbound;
	if (s=="Outbound"||s=="outbound"||s=="out") return Outbound;
	if (s=="Both"   ||s=="both"   ||s=="b")  return Both;
	throw invalid_argument("Invalid Direction");
}

Verdict ACLManager::fromVerdict(const string &s) {
	if (s=="DENY"||s=="deny")   return DENY;
	if (s=="PERMIT"||s=="permit") return PERMIT;
	throw invalid_argument("Invalid Verdict");
}





Protocol ACLManager::fromProto(const string &s) {
	if (s=="TCP"||s=="tcp")    return TCP;
	if (s=="UDP"||s=="udp")    return UDP;
	if (s=="ICMP"||s=="icmp")  return ICMP;
	if (s=="All"||s=="all"||s=="IP"||s=="ip") return All;
	throw invalid_argument("Bad Proto");
}

PortOp ACLManager::fromPortOp(const string &s) {
	if (s=="-eq" || s=="eq" || s=="=")   return Eq;
	if (s=="-neq"|| s=="neq"|| s=="!=")  return Neq;
	if (s=="-gt" || s=="gt" || s==">")   return Gt;
	if (s=="-lt" || s=="lt" || s=="<")   return Lt;
	throw invalid_argument("Bad PortOp");
}


vector<string> ACLManager::split(const string &s, char d){
	vector<string> v; string t; istringstream ss(s);
	while(getline(ss,t,d)) v.push_back(t);
	return v;
}

ACE ACLManager::parseACE(const string &line) {
	stringstream ss(line);
	string tok;
	ACE ace;
	ace.priority    = 100;
	ace.direction   = Both;
	ace.protocol    = All;
	ace.icmpType    = -1;
	ace.tcpFlags    = 0;
	ace.srcIp=ace.srcMask=ace.dstIp=ace.dstmask=0;
	ace.id = rand()%10000+1;

	// 1) priority
	if(ss>>tok) ace.priority=stoi(tok);
	// 2) direction
	if(ss>>tok) ace.direction=fromDir(tok);
	// 3) verdict
	if(!(ss>>tok)) throw invalid_argument("Missing action");
	ace.action=fromVerdict(tok);
	// 4) protocol
	if(!(ss>>tok)) throw invalid_argument("Missing proto");
	ace.protocol=fromProto(tok);

	// 5) source IP/mask
	if(!(ss>>tok)) throw invalid_argument("Missing src IP");
	if(tok=="any"){ ace.srcIp=ace.srcMask=0; }
	else if(tok=="host"){
		ss>>tok;
		ace.srcIp= parseIp("host "+tok);
		ace.srcMask=0xFFFFFFFF;
	} else {
		ace.srcIp=parseIp(tok);
		if(tok.find('/')!=string::npos)
			ace.srcMask=parseMask(tok);
		else{
			ss>>tok;
			if(tok=="host") throw invalid_argument("Use 'host <IP>'");
			ace.srcMask=parseMask(tok);
		}
	}

	// 6) dest IP/mask
	if(!(ss>>tok)) throw invalid_argument("Missing dst IP");
	if(tok=="any"){
		streampos p=ss.tellg(); string pk;
		if(ss>>pk && pk=="host"){
			ss>>tok;
			ace.dstIp= parseIp("host "+tok);
			ace.dstmask=0xFFFFFFFF;
		} else {
			ace.dstIp=ace.dstmask=0;
			ss.seekg(p);
		}
	}
	else if(tok=="host"){
		ss>>tok;
		ace.dstIp= parseIp("host "+tok);
		ace.dstmask=0xFFFFFFFF;
	} else {
		ace.dstIp=parseIp(tok);
		if(tok.find('/')!=string::npos)
			ace.dstmask=parseMask(tok);
		else{
			ss>>tok;
			if(tok=="host") throw invalid_argument("Use 'host <IP>'");
			ace.dstmask=parseMask(tok);
		}
	}

	// 7) port operation & number (TCP/UDP only)
	if (ace.protocol == TCP || ace.protocol == UDP) {
		streampos beforePortCheck = ss.tellg();  // Save position before checking
		string nextToken;
		
		if (ss >> nextToken) {  // Peek at next token
			// Case 1: Port operation (e.g., "-eq 80")
			if (nextToken.rfind("-", 0) == 0) {  // Starts with '-'
				ace.portOp = fromPortOp(nextToken);
				if (!(ss >> nextToken)) throw invalid_argument("Missing port");
				ace.port = stoi(nextToken);
			} 
			// Case 2: Direct port number (e.g., "80")
			else if (isdigit(nextToken[0])) {
				ace.portOp = Eq;  // Default to "equal"
				ace.port = stoi(nextToken);
			}
			// Case 3: Not a port (e.g., "flags SYN") → Skip and set default
			else {
				ss.seekg(beforePortCheck);  // Rewind
				ace.port = 0;               // Default port = 0
				ace.portOp = Eq;            // Default operation = Eq
			}
		} else {
			// No more tokens → default values
			ace.port = 0;
			ace.portOp = Eq;
		}
	}
	// 8) flags (TCP) or ICMP type
	if(ace.protocol==TCP) {
		if(ss>>tok && tok=="flags") {
			if(!(ss>>tok)) throw invalid_argument("Missing flags");
			for(auto &f : split(tok,'/')) {
				if(f=="SYN") ace.tcpFlags |= TCP_SYN;
				else if(f=="ACK") ace.tcpFlags |= TCP_ACK;
				else if(f=="FIN") ace.tcpFlags |= TCP_FIN;
				else if(f=="RST") ace.tcpFlags |= TCP_RST;
				else if(f=="PSH") ace.tcpFlags |= TCP_PSH;
				else if(f=="URG") ace.tcpFlags |= TCP_URG;
				else if(f=="ECE") ace.tcpFlags |= TCP_ECE;
				else if(f=="CWR") ace.tcpFlags |= TCP_CWR;
				else if(f=="established" || f == "estab" || "3" || "hand") ace.established = true;
				else throw invalid_argument("Unknown flag: "+f);
			}
		}
	}
	else if(ace.protocol==ICMP) {
		if(ss>>tok) {
			if(tok=="echo")       ace.icmpType = 8; 
			else if(tok=="echo-reply") ace.icmpType = 0;
			else throw invalid_argument("Unknown ICMP type: "+tok);
		}
	}

	addACE(ace);

	return ace;
}


string ACLManager::ipToStr(uint32_t ip) {
	struct in_addr a; a.s_addr=htonl(ip);
	char b[INET_ADDRSTRLEN];
	inet_ntop(AF_INET,&a,b,sizeof(b));
	return b;
}
string ACLManager::maskToStr(const uint32_t& m) {
	if(m==0) return "0.0.0.0";
	if(m==0xFFFFFFFF) return "255.255.255.255";
	uint32_t mask = m; 
	int c = 0; 
	while (mask & 0x80000000) { 
		c++; 
		mask <<= 1; 
	}
	return "/"+to_string(c);
}
string ACLManager::tcpFlagsToString(const uint8_t& flags) {
	vector<string> names;
	if (flags & TCP_FIN)  names.push_back("FIN");
	if (flags & TCP_SYN)  names.push_back("SYN");
	if (flags & TCP_RST)  names.push_back("RST");
	if (flags & TCP_PSH)  names.push_back("PSH");
	if (flags & TCP_ACK)  names.push_back("ACK");
	if (flags & TCP_URG)  names.push_back("URG");
	if (flags & TCP_ECE)  names.push_back("ECE");
	if (flags & TCP_CWR)  names.push_back("CWR");
	if (names.empty())    return "none";
	
	// join with '/'
	string result = names[0];
	for (size_t i = 1; i < names.size(); ++i) {
		result += "/" + names[i];
	}
	return result;
}
string ACLManager::icmpTypeToString(const uint8_t& type) {
	switch (type) {
		case 0:  return "echo-reply";
		case 3:  return "destination-unreachable";
		case 4:  return "source-quench";
		case 5:  return "redirect";
		case 8:  return "echo";
		case 11: return "time-exceeded";
		case 12: return "parameter-problem";
		case 13: return "timestamp";
		case 14: return "timestamp-reply";
		case 15: return "information-request";
		case 16: return "information-reply";
		default: {
			return "type-" + to_string(type);
		}
	}
}

void ACLManager::printACE(const ACE &a){
	cout<<"ACE ID: "<<a.id<<"\n"
		<<"Priority: "<<a.priority<<"\n"
		<<"Direction: "<<(a.direction==Inbound?"Inbound":
						 a.direction==Outbound?"Outbound":"Both")<<"\n"
		<<"Action: "<<(a.action==DENY?"DENY":"PERMIT")<<"\n"
		<<"Protocol: "<<(a.protocol==TCP?"TCP":
					   a.protocol==UDP?"UDP":
					   a.protocol==ICMP?"ICMP":"All")<<"\n"
		<<"Src IP: "<<ipToStr(a.srcIp)<<" "<<maskToStr(a.srcMask)<<"\n"
		<<"Dst IP: "<<ipToStr(a.dstIp)<<" "<<maskToStr(a.dstmask)<<"\n"
		<<"PortOp: "<<(a.portOp==Eq?"Eq":a.portOp==Neq?"Neq":a.portOp==Gt?"Gt":"Lt")<<" Port: "<<a.port<<"\n"
		<<"TCP Flags:"<<tcpFlagsToString(a.tcpFlags)<<"\n"
		<<"ICMP Type: "<<icmpTypeToString(a.icmpType)<<"\n"
		<<"-----------------------------\n";
}

