#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <deque>
#include <mutex>
#include <thread>
#include <chrono>
#include <condition_variable>
#include <atomic>

std::mutex mtx;
std::condition_variable cv;
std::atomic<bool> running(true); // Atomic flag to stop the thread safely
bool updated = false;

// Function to monitor the log file
void monitorLogs(const std::string& logFile, std::map<std::string, int>& threatCount, std::deque<std::string>& lastLogs) {
    std::ifstream file(logFile, std::ios::in);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Error: Could not open log file: " << logFile << "\n";
        return;
    }

    while (running) {
        while (std::getline(file, line)) {
            std::unique_lock<std::mutex> lock(mtx);

            // Add line to the lastLogs deque
            if (lastLogs.size() >= 10) {
                lastLogs.pop_front(); // Maintain only the last 10 logs
            }
            lastLogs.push_back(line);

            // Check for threats
            if (line.find("malicious") != std::string::npos) {
                std::cout << "Threat detected: " << line << std::endl;
                threatCount["malicious"]++;
            } else if (line.find("attack") != std::string::npos) {
                std::cout << "Threat detected: " << line << std::endl;
                threatCount["attack"]++;
            }

            updated = true;
            cv.notify_all();
        }

        // Clear EOF and prepare to read new log entries
        if (file.eof()) {
            file.clear();
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    std::cout << "Log monitoring stopped.\n";
}

// Function to display threat statistics
void displayStats(const std::map<std::string, int>& threatCount) {
    std::unique_lock<std::mutex> lock(mtx);
    std::cout << "\nThreat Statistics:\n";
    for (const auto& pair : threatCount) {
        std::cout << pair.first << ": " << pair.second << " occurrences\n";
    }
    if (threatCount.empty()) {
        std::cout << "No threats detected so far.\n";
    }
}

// Function to display the last 10 log entries
void displayLastLogs(const std::deque<std::string>& lastLogs) {
    std::unique_lock<std::mutex> lock(mtx);
    std::cout << "\nLast 10 Log Entries:\n";
    for (const auto& log : lastLogs) {
        std::cout << log << "\n";
    }
    if (lastLogs.empty()) {
        std::cout << "No logs available.\n";
    }
}

int main() {
    std::string logFile = "/private/var/log/system.log"; // macOS system log file path
    std::map<std::string, int> threatCount;
    std::deque<std::string> lastLogs; // Store the last 10 logs

    std::cout << "Starting Real-Time Threat Detection System...\n";

    // Launch the log monitoring in a separate thread
    std::thread monitorThread(monitorLogs, logFile, std::ref(threatCount), std::ref(lastLogs));

    // Main program loop
    while (true) {
        std::cout << "\nOptions:\n";
        std::cout << "1. Display Threat Statistics\n";
        std::cout << "2. Display Last 10 Logs\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter your choice: ";

        int choice;
        std::cin >> choice;

        if (choice == 1) {
            displayStats(threatCount);
        } else if (choice == 2) {
            displayLastLogs(lastLogs);
        } else if (choice == 3) {
            std::cout << "Exiting...\n";
            running = false; // Signal the thread to stop
            cv.notify_all(); // Wake the thread if waiting
            break;
        } else {
            std::cout << "Invalid choice. Try again.\n";
        }
    }

    // Wait for the monitoring thread to finish
    if (monitorThread.joinable()) {
        monitorThread.join();
    }

    return 0;
}

