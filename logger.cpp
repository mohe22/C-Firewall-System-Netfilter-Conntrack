#include "log.hpp"
#include <iostream>

using namespace std;

namespace Logger {
	shared_ptr<spdlog::logger> app_logger;

	void init(const string& app_logfile, spdlog::level::level_enum level) {
		try {
			// Rotating file sink (5MB max, 3 rotated files)
			auto app_file_sink = make_shared<spdlog::sinks::rotating_file_sink_mt>(
				app_logfile, 1024 * 1024 * 5, 3);

			// Create logger with only file sink (no console)
			app_logger = make_shared<spdlog::logger>("APP", 
				spdlog::sinks_init_list({app_file_sink}));

			// Set log pattern
			app_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] %v");

			// Set log level and flush policy
			app_logger->set_level(level);
			app_logger->flush_on(spdlog::level::warn);

			spdlog::register_logger(app_logger);
		} catch (const spdlog::spdlog_ex& ex) {
			cerr << "Log initialization failed: " << ex.what() << endl;
		}
	}

	void shutdown() {
		spdlog::shutdown();
	}
}
