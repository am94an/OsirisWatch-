# Network Traffic Collection Module

This module is responsible for capturing, analyzing, and processing network traffic in real-time. It serves as the data collection component of the OsirisWatch IDS system.

## Authentication Setup

1. Open `config.py` and set your credentials:
```python
# Default credentials
USERNAME = "osiris"
PASSWORD = "osiris"

# For production, use environment variables:
# USERNAME = os.getenv('OSIRIS_USERNAME')
# PASSWORD = os.getenv('OSIRIS_PASSWORD')
```

2. For security in production:
   - Create a `.env` file in the collect script directory
   - Add your credentials:
   ```
   OSIRIS_USERNAME=your_username
   OSIRIS_PASSWORD=your_password
   ```
   - Never commit the `.env` file to version control

## Components

### 1. Packet Sniffer (`processor/packet_sniffer.py`)
- Real-time network packet capture
- Flow-based traffic analysis
- Attack pattern detection
- WebSocket integration for real-time alerts

### 2. Flow Analysis (`processor/flow.py`)
- Network flow tracking
- Flow feature extraction
- Flow termination logic
- Statistical analysis of network flows

### 3. Feature Extraction (`processor/feature_extractor.py`)
- Network traffic feature calculation
- Statistical analysis
- Pattern recognition
- Feature normalization

### 4. Utilities
- `utils/auth.py`: Authentication and token management
- `utils/logger.py`: Logging configuration
- `utils/network_utils.py`: Network utility functions

## Configuration

The module is configured through `config.py`:
```python
API_URL = "http://localhost:8000/predictions/"
SNIF_FILTER = "ip"
AUTH_URL = "http://localhost:8000/api/token/"
AUTH_REFRESH_URL = "http://localhost:8000/api/token/refresh/"
```

## Usage

1. Start the collection script:
```bash
python main.py
```

2. The script will:
   - Authenticate with the backend server
   - Start capturing network packets
   - Process and analyze network flows
   - Send data to the prediction API
   - Generate real-time alerts

## Features

- **Real-time Monitoring**: Continuous network traffic analysis
- **Flow-based Analysis**: Grouping packets into network flows
- **Attack Detection**: Identification of potential security threats
- **Data Streaming**: Real-time data transmission to backend
- **WebSocket Integration**: Instant alert delivery
- **Token-based Authentication**: Secure communication with backend

## Performance Considerations

- Flow timeout: 120 seconds
- Maximum flow duration: 3600 seconds (1 hour)
- Maximum packets per flow: 1000
- Alert thresholds:
  - Packets per second: 1000
  - Bytes per second: 1000000
  - SYN ratio: 0.7
  - RST ratio: 0.3

## Error Handling

- Automatic token refresh on authentication failure
- Graceful error recovery
- Comprehensive logging
- WebSocket reconnection logic

## Dependencies

- scapy: Network packet capture
- websockets: Real-time communication
- requests: HTTP communication
- numpy: Numerical computations
- pandas: Data processing
- python-dotenv: Environment management 