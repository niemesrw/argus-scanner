# Argus Network Security Scanner

A continuous network security monitoring agent designed to run on Raspberry Pi, with support for local development on macOS.

## ⚠️ Security Notice

**This tool is designed for authorized security testing only.** Use this software only on networks you own or have explicit permission to test. Unauthorized network scanning may be illegal in your jurisdiction.

## Features

- 🔍 **Network Discovery**: Automatic detection of devices on your network
- 🛡️ **Vulnerability Scanning**: Identifies known vulnerabilities using CVE databases
- 🚨 **Real-time Alerts**: Email and Slack notifications for critical findings
- 📊 **Web Dashboard**: Lightweight interface for monitoring network security
- 🔄 **Continuous Monitoring**: Scheduled scans with configurable intervals
- 🐳 **Containerized**: Easy deployment with Docker
- 🌐 **Multi-Architecture**: Supports ARM64 (Raspberry Pi) and AMD64 (x86)

## Quick Start

### Local Development (macOS)

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/argus-scanner.git
   cd argus-scanner
   ```

2. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the dashboard**
   ```
   http://localhost:8080
   ```

### Raspberry Pi Deployment

1. **Prerequisites**
   - Raspberry Pi 4 (recommended) with Raspbian OS
   - Docker and Docker Compose installed
   - Network access to target subnet

2. **Deploy using the script**
   ```bash
   ./scripts/deploy.sh
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ARGUS_ENV` | Environment (development/production) | production |
| `ARGUS_NETWORK_RANGE` | Network range to scan | 192.168.1.0/24 |
| `ARGUS_SCAN_INTERVAL` | Scan interval in seconds | 3600 |
| `ARGUS_MOCK_MODE` | Use mock data (for development) | false |

### Alert Configuration

Configure alerts by setting these environment variables:

**Email Alerts:**
- `ARGUS_ALERT_EMAIL_ENABLED`: Enable email alerts
- `ARGUS_SMTP_HOST`: SMTP server host
- `ARGUS_SMTP_PORT`: SMTP server port
- `ARGUS_SMTP_USERNAME`: SMTP username
- `ARGUS_SMTP_PASSWORD`: SMTP password
- `ARGUS_ALERT_FROM`: Sender email address
- `ARGUS_ALERT_TO`: Comma-separated recipient emails

**Slack Alerts:**
- `ARGUS_ALERT_SLACK_ENABLED`: Enable Slack alerts
- `ARGUS_SLACK_WEBHOOK`: Slack webhook URL

## GitHub Actions Deployment

### Setup

1. **Configure GitHub Secrets:**
   - `PI_HOST`: Raspberry Pi hostname/IP
   - `PI_USERNAME`: SSH username
   - `PI_SSH_KEY`: Private SSH key for authentication
   - `PI_NETWORK_RANGE`: Network range to scan
   - `ARGUS_SECRET_KEY`: Secret key for web app
   - Alert configuration secrets (optional)

2. **Enable GitHub Packages:**
   - Go to Settings → Actions → General
   - Enable "Read and write permissions"

3. **Deploy:**
   - Push to main branch triggers automatic deployment
   - Or manually trigger via Actions tab

## Development

### Project Structure
```
argus-scanner/
├── docker/              # Docker configurations
├── src/                 # Source code
│   ├── scanner/        # Network scanning modules
│   ├── database/       # Database models
│   ├── web/           # Web dashboard
│   └── alerts/        # Alert management
├── tests/              # Test files
└── .github/workflows/  # CI/CD pipelines
```

### Running Tests
```bash
# Install dev dependencies
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests
pytest tests/ -v --cov=src
```

### Mock Mode
For safe development, enable mock mode:
```bash
ARGUS_MOCK_MODE=true docker-compose up
```

## API Endpoints

- `GET /api/stats` - Dashboard statistics
- `GET /api/devices` - List all devices
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/alerts` - List alerts
- `POST /api/scan/start` - Trigger manual scan

## Security Considerations

1. **Network Isolation**: Run Argus on an isolated network segment
2. **Access Control**: Secure the web dashboard with authentication
3. **Rate Limiting**: Scans are throttled to prevent network disruption
4. **Logging**: All scanning activities are logged for audit purposes
5. **No Exploitation**: The tool identifies but does not exploit vulnerabilities

## Troubleshooting

### Common Issues

1. **Permission Denied (nmap)**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   ```

2. **Port 8080 Already in Use**
   ```bash
   # Change port in docker-compose.yml
   ports:
     - "8081:8080"
   ```

3. **Database Lock Error**
   ```bash
   # Remove lock file
   rm data/argus.db-journal
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software.

## Acknowledgments

- Built with Python, Flask, and nmap
- Uses Bootstrap for the web interface
- Inspired by various network security tools