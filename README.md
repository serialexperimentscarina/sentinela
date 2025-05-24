# Sentinela

A configurable file integrity monitoring tool for Linux.

## Getting Started

### Prerequisites

- **nlohmann-json3-dev**
- **G++**

### Installing

1. **Clone the repository:**
   ```
   git clone https://github.com/serialexperimentscarina/sentinela.git
   ```
2. **Install dependencies:**
   ```
   sudo apt install nlohmann-json3-dev
   ```
3. **Run the installation script:**
   ```
   chmod +x install.sh
   sudo ./install.sh
   ```

### Usage

After installation, the tool will begin running as a background Linux service under the name 'sentinela.service'. The tool can be configured by making changes to the config file located in 'etc/sentinela/config.toml'.
To uninstall, run 'uninstall.sh' from any folder
