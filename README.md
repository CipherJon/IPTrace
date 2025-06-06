# IP Trace

A Python application that aggregates geolocation data from multiple free IP lookup APIs. This tool provides comprehensive information about IP addresses by querying various services and combining their results.

## Features

- Query multiple IP geolocation APIs simultaneously
- Rate limiting to respect API constraints
- Beautiful console output using Rich
- Asynchronous requests for better performance
- Aggregated results from multiple sources
- Error handling and graceful degradation

## Supported APIs

- IP-API.com
- ipapi.co
- ipwhois.io
- BigDataCloud

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/ip-trace.git
cd ip-trace
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python ip_trace.py
```

Enter an IP address when prompted. The application will query multiple APIs and display the aggregated results in a formatted table.

To exit, type 'quit' when prompted for an IP address.

## Rate Limits

The application implements rate limiting to respect API constraints:
- IP-API.com: 45 requests per minute
- ipapi.co: 1,000 requests per day
- ipwhois.io: 10,000 requests per month
- BigDataCloud: No strict limits

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
