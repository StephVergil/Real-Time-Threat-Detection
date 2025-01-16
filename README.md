# Real-Time Threat Detection System

## Overview
The Real-Time Threat Detection System is designed to monitor log files for malicious activity or potential security threats. It identifies keywords such as "malicious" and "attack" in real-time, maintains statistics on detected threats, and provides users with quick insights into the last few log entries.

## Purpose and Benefits

This system is particularly useful in cybersecurity for:

- **Real-Time Monitoring**: Continuously scans log files for suspicious activity, reducing the time to detect threats.
- **Threat Analysis**: Tracks the occurrence of specific threats over time, providing valuable insights into system vulnerabilities.
- **User-Friendly Interface**: Offers clear options to view threat statistics or recent logs, empowering users to act quickly.
- **Efficiency**: Uses multi-threading for concurrent log monitoring and user interaction, ensuring minimal delay.

## How the Code Works

### Key Features

1. **Log Monitoring**:
   - The `monitorLogs` function continuously reads a specified log file.
   - Detects predefined keywords ("malicious" and "attack") and updates a threat counter.
   - Maintains a deque of the last 10 log entries for quick reference.

2. **Thread Safety**:
   - Uses `std::mutex` and `std::condition_variable` to ensure safe access to shared data across threads.
   - Atomic variables (`std::atomic`) ensure thread-safe stopping mechanisms.

3. **User Interaction**:
   - Provides options to display threat statistics, view recent logs, or exit the program.
   - The `displayStats` function summarizes detected threats.
   - The `displayLastLogs` function prints the last 10 log entries.

4. **Graceful Shutdown**:
   - Ensures the monitoring thread terminates safely when the program exits.

### Code Breakdown

#### 1. **Main Function**
- Initializes variables such as `logFile`, `threatCount`, and `lastLogs`.
- Launches the `monitorLogs` function in a separate thread for non-blocking log monitoring.
- Provides a menu-driven interface for user interaction.

#### 2. **Log Monitoring**
```cpp
void monitorLogs(const std::string& logFile, std::map<std::string, int>& threatCount, std::deque<std::string>& lastLogs) {
    std::ifstream file(logFile, std::ios::in);
    ...
    while (running) {
        while (std::getline(file, line)) {
            std::unique_lock<std::mutex> lock(mtx);
            ...
            if (line.find("malicious") != std::string::npos) {
                threatCount["malicious"]++;
            }
            ...
        }
        ...
    }
}
```
- Opens the log file for reading and continuously scans for new entries.
- Updates the `threatCount` map and `lastLogs` deque for each detected log entry.

#### 3. **Displaying Data**
- `displayStats` and `displayLastLogs` functions provide user-friendly outputs of threat data and log history.

```cpp
void displayStats(const std::map<std::string, int>& threatCount) {
    std::unique_lock<std::mutex> lock(mtx);
    for (const auto& pair : threatCount) {
        std::cout << pair.first << ": " << pair.second << " occurrences\n";
    }
}

void displayLastLogs(const std::deque<std::string>& lastLogs) {
    for (const auto& log : lastLogs) {
        std::cout << log << "\n";
    }
}
```

#### 4. **Threading and Synchronization**
- `std::mutex` ensures that only one thread accesses shared data at a time.
- `std::condition_variable` wakes up threads waiting for changes in shared data.

```cpp
std::mutex mtx;
std::condition_variable cv;
std::atomic<bool> running(true);
```

## Use Cases

1. **Enterprise Security**: Helps IT administrators monitor server logs for potential breaches.
2. **Compliance Audits**: Assists in detecting and reporting unauthorized access attempts.
3. **Forensic Analysis**: Provides insights into recent activities before a system failure or attack.

## Future Enhancements

- **Configurable Keywords**: Allow users to specify custom keywords for threat detection.
- **GUI Integration**: Develop a graphical interface for easier interaction.
- **Enhanced Threat Analysis**: Incorporate machine learning to identify complex patterns of malicious behavior.
- **Cloud Support**: Enable monitoring of logs stored in cloud environments.

## Resources

Here are additional resources to help understand and expand this system:

1. **C++ Documentation**: [cplusplus.com](https://www.cplusplus.com) - Comprehensive guide on C++ libraries and syntax.
2. **Multi-threading in C++**: [cppreference.com](https://en.cppreference.com/w/cpp/thread) - Details on thread handling and synchronization.
3. **Cybersecurity Best Practices**: [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Guidelines for managing and reducing cybersecurity risks.
4. **Log Management Tools**: Explore tools like [ELK Stack](https://www.elastic.co/what-is/elk-stack) for advanced log analysis.
5. **Deque Container in C++**: [std::deque Documentation](https://en.cppreference.com/w/cpp/container/deque) - Explanation of the deque container used in log management.

This program is a foundational tool for real-time threat detection, emphasizing the importance of proactive cybersecurity measures.
