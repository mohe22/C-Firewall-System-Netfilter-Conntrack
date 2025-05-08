#include <iostream>
#include <fstream>
#include "aclManager.hpp"
#include "firewall.hpp"
#include "log.hpp"

#include <boost/spirit/include/qi.hpp>


using namespace std;

void help();
void addRules(ACLManager& manager);
void deleteRule(ACLManager& manage);
int main() {
	try {
		Logger::init("my_app.log", spdlog::level::debug);


	
		ACLManager manager;
		Firewall fw(manager);
		string choice;

	
		manager.parseACE("100 in deny tcp 192.168.100.118/32  any flags established");
		manager.parseACE("102 both permit tcp any any");
		manager.parseACE("105 both permit udp any any");
	

		while (true) {
			cout << "NFWall> ";
			getline(cin, choice);

			if (choice == "help") {
				help();
			} else if (choice == "add-rules" || choice == "add" || choice == "add rule") {
				addRules(manager);
			}else if (choice == "show-rules" || choice == "show" || choice == "show rules" || choice == "display") {
			   manager.printACEs();
			} else if (choice == "delete-rule" || choice == "delete" || choice == "d" || choice == "delete rule") {
				manager.printACEs();
				cout << "\n\n\n";
				deleteRule(manager);
			} else if (choice == "exit") {
				cout << "Exiting...\n";
				break;
			}else if(choice == "defualt-action"){
				// TODO
			} else if (!choice.empty()) {
				cout << "Unknown command. Type 'help' for available commands.\n";
			}
		}
	}
	catch(const exception& e) {
		cerr << "Fatal error: " << e.what() << '\n';
		return 1;
	}
	// Cleanup
	Logger::shutdown();
	return 0;
}

void addRules(ACLManager& manager) {
	string command;
	
	while (true) {
		cout << "NFWall/rules> ";
		getline(cin, command);
		
		if (command == "done" || command == "back" || command == "exist" || command == "home") break;
		if (command.empty()) continue;
		
		try {
			manager.parseACE(command);
		
			cout << "Successfully added rule.\n";
		} catch (const exception& e) {
			cerr << "Error: " << e.what() << '\n';
		}
	}
}

void deleteRule(ACLManager& manager) {
	string command;

	do {
		cout << "NFWall/rules/delete> ";
		getline(cin, command);

		if (command == "done" || command == "back" || command == "exist" || command == "home")
			break;

		try {
			int ruleId = stoi(command);
			if (manager.deleteACE(ruleId)) {
				cout << "Rule with ID " << ruleId << " deleted successfully.\n";
			} else {
				cout << "Error: Rule not found.\n";
			}
		} catch (const invalid_argument&) {
			cout << "Error: Please enter a valid numeric rule ID.\n";
		} catch (const out_of_range&) {
			cout << "Error: Rule ID is out of range.\n";
		}
	} while (true);
}

void help() {
	cout << "\nNFWall Firewall Management System\n";
	cout << "========================================\n";
	cout << "Command Syntax:\n";
	cout << "<priority>  <direction> <action> <protocol> <source> [mask] <destination> [mask] [options]\n\n";
	
	cout << "Parameters:\n";
	cout << "  priority:    0-1000 | (priority of the ACE lower more priority)\n";
	cout << "  direction:  'in' (inbound) | 'out' (outbound) | 'both' (in/out) | (omit for both directions)\n";
	cout << "  action:     'permit' (allow) | 'deny' (block)\n";
	cout << "  protocol:   'ip' | 'tcp' | 'udp' | 'icmp'\n";
	cout << "  source/dest: 'any' | 'host <IP>' | '<IP> [<mask>]'\n\n";
	
	cout << "Port/ICMP Options:\n";
	cout << "  TCP/UDP:    'eq <port>' | 'range <start> <end>' | 'established'\n";
	cout << "  ICMP:       'echo' | 'echo-reply' | 'redirect' | 'unreachable' | 'ping' (allow  only echo/echo-reply)\n";
	cout << "  TCP Flags:  'flags syn/ack' (combine with /)\n\n";
	
	cout << "Available Commands:\n";
	cout << "  1. add-rules    		- Interactive rule addition\n";
	cout << "  3. show-rules   		- Display current rules\n";
	cout << "  4. delete-rule  		- Remove a rule by ID\n";
	cout << "  5. clear-rules  		- Remove all rules\n";
	cout << "  6. help         		- Show this help\n";
	cout << "  7. exit         		- Exit the program\n\n";
	cout << "  8. defualt-action    - Defualt action if not ACE (rule) fount\n";

	cout << "Examples:\n";
	cout << "  Basic Rules:\n";
	cout << "   0 permit ip any any                     # Allow all traffic\n";
	cout << "   1 deny tcp any any eq 22                # Block all SSH\n";
	cout << "   2 in permit udp any any eq 53           # Allow inbound DNS\n\n";
	
	cout << "  Network Rules:\n";
	cout << "   1 out deny ip 192.168.1.0 0.0.0.255 any # Block outbound from /24 network\n";
	cout << "   3 permit icmp host 10.0.0.1 any echo    # Allow ping from specific host\n\n";
	
	cout << "  Advanced Rules:\n";
	cout << "   0 in permit tcp any any established     # Allow established TCP\n";
	cout << "   2 deny tcp any any flags syn            # Block SYN scans\n";
	cout << "   3 permit tcp any any range 50000 51000  # Allow FTP data ports\n\n";
	
	cout << "Note:\n";
	cout << "      'host' keyword specifies a single IP (e.g., host 192.168.1.1)\n";
}