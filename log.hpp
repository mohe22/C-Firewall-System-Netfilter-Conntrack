#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <memory>

using namespace std;

namespace Logger {
	// General application logger
	extern shared_ptr<spdlog::logger> app_logger;

	// Initialize logger
	void init(
		const string& app_logfile = "app.log",
		spdlog::level::level_enum level = spdlog::level::info
	);

	// Shutdown logger
	void shutdown();
}
