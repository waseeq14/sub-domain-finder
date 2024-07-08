```markdown
# Sub Domain Finder

A comprehensive tool for sub-domain enumeration and web information gathering. This script provides functionalities to gather sub-domains using a wordlist and APIs like VirusTotal, DNSDumpster, and SecurityTrails.

## Features

- Sub-domain enumeration using a wordlist
- Sub-domain enumeration using APIs
- Manage API keys for VirusTotal and SecurityTrails
- Save and load API keys from a JSON file
- Recursive sub-domain discovery

## Requirements

- Python 3.x
- Required Python packages (install via `pip install -r requirements.txt`):
  - `argparse`
  - `pyfiglet`
  - `requests`
  - `dnspython`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/sub-domain-finder.git
    cd sub-domain-finder
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Command Line Arguments

- `--domain`: The domain to gather information about.
- `--wordlist`: The wordlist file for sub-domain and directory enumeration.
- `--output`: The file to save the output.
- `--setapi`: Set API key for the services.
- `--getapi`: Print currently set API keys.
- `--clearapi`: Remove currently set API keys.
- `--depth`: Depth for recursive subdomain discovery (optional, default is 2).

### Example Usage

#### Sub-domain Enumeration Using Wordlist

```sh
python sub_domain_finder.py --domain example.com --wordlist wordlist.txt --output output.txt
```

#### Sub-domain Enumeration Using API

```sh
python sub_domain_finder.py --domain example.com --depth 3 --output output.txt
```

#### Set API Keys

```sh
python sub_domain_finder.py --setapi
```

#### Get API Keys

```sh
python sub_domain_finder.py --getapi
```

#### Clear API Keys

```sh
python sub_domain_finder.py --clearapi
```

### Running the Script

1. To start the script, simply run:
    ```sh
    python sub_domain_finder.py
    ```

2. Follow the on-screen menu to choose the desired option.

## API Key Management

### Set API Keys

The script supports API key management for VirusTotal and SecurityTrails. When setting API keys, you'll be prompted to enter the key for each service.

### Clear API Keys

You can choose to clear all API keys or selectively remove keys for specific services.

## Output

The results of the sub-domain enumeration will be printed to the console and optionally saved to an output file if specified using the `--output` argument.
```