# Extr4ct0r

A powerful JavaScript security analysis tool written in Go, designed to help bug hunters and pentester's to extract JavaScript files, discover endpoints, and identify sensitive information exposures in web applications.

## Features

- Extract JavaScript files from web pages
- Discover endpoints and API routes
- Detect sensitive information in JavaScript files including:
  - API Keys (Google, Firebase, AWS, etc.)
  - Authentication Tokens
  - Private Keys
  - Database Connection Strings
  - Passwords and Credentials
  - Cloud Service Configurations

## Installation

### Prerequisites

extr4ct0r requires Go 1.20 to install successfully. To install, just run the below command
```bash
go install github.com/AnGrY-Althaf/extr4ct0r@latest
```

### Building from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/extr4ct0r.git
cd extr4ct0r

# Install dependencies
go mod init extr4ct0r
go get github.com/PuerkitoBio/goquery
go get github.com/fatih/color

# Build the executable
go build -o extr4ct0r
```

## Usage

### Command Line
```bash
# Scan a single URL
extr4ct0r -u https://example.com

# Scan multiple URLs
extr4ct0r -u https://example1.com,https://example2.com

# Scan URLs from a file
cat urls.txt | ./extr4ct0r
```

### Interactive Menu (Not for piped input !!)
After scanning, you'll be presented with an interactive menu:
```
1. Extract all JavaScript files
2. Find all links and endpoints
3. Check for exposures
4. Exit
```

### Output
Results are saved in the `output` directory with timestamps:
- `javascript-files.txt` - List of JavaScript files
- `endpoints.txt` - List of discovered endpoints
- `exposures.txt` - Sensitive information findings

## Detection Patterns

Extr4ct0r can detect various types of sensitive information including:

### API Keys & Authentication
- Google API Keys
- Firebase Keys
- AWS Access Keys
- OAuth Tokens
- Bearer Tokens

### Credentials & Secrets
- Basic Authentication
- JWT Tokens
- Private Keys (RSA, SSH, PGP)
- Passwords and Credentials

### Service-Specific Keys
- Stripe API Keys
- PayPal/Braintree Tokens
- Mailgun API Keys
- Square Access Tokens
- Slack Tokens
- Heroku API Keys

### Infrastructure
- AWS S3 URLs
- Database Connection Strings
- Internal IPs and Staging URLs
