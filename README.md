# Keyhawk

**Keyhawk** is a Python tool that scans files for API tokens using regex patterns, with optional validation against live APIs to check if the tokens are active. It’s fast, colorful, and perfect for security researchers, developers, or anyone hunting for exposed credentials.

## Features
- **Token Detection**: Identifies API keys and secrets from a customizable list of patterns (`regex.json`).
- **Validation**: Optionally validates tokens using API calls .
- **Manual Testing**: Provides `curl` commands to manually verify tokens.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/tokensnipe.git
   cd tokensnipe
   pip install -r requirements.txt

## Usage
```bash
python3 keyhawk.py -f <file> [--validate] [--manual]
```
### Options
- **-f, --file**: Path to the file to scan (required).
- **--validate**: Validate found tokens against their respective APIs.
- **--manual**: Print curl commands for manual token testing.

## Example
![Screenshot 2025-03-12 1925223](https://github.com/user-attachments/assets/be815b34-1212-4713-9754-ea8244d69c6b)

##Configuration
- **regex.json** : Defines token patterns. Edit to add or modify token types.
- **verification_methods.yaml** : Specifies the rules for validation. Update to support new validation tokens.

