#!/usr/bin/env python3

import argparse
import json
import re
import sys
import subprocess
import yaml
from termcolor import colored
from multiprocessing import Pool

class APIFinder:
    def __init__(self, secrets_file, regex_file="regex.json"):
        self.secrets_file = secrets_file
        self.regex_file = regex_file
        self.patterns = self._load_patterns()
        self.results = {}

    def _load_patterns(self):
        try:
            with open(self.regex_file, 'r') as f:
                return json.load(f)
        except IOError:
            print(colored(f"Error: Regex file '{self.regex_file}' not found", 'red'))
            sys.exit(1)
        except json.JSONDecodeError:
            print(colored(f"Error: Invalid JSON in '{self.regex_file}'", 'red'))
            sys.exit(1)

    def _load_secrets(self):
        try:
            with open(self.secrets_file, 'r') as f:
                return f.read()
        except IOError:
            print(colored(f"Error: Secrets file '{self.secrets_file}' not found", 'red'))
            sys.exit(1)
        except Exception as e:
            print(colored(f"Error reading secrets file: {str(e)}", 'red'))
            sys.exit(1)

    def find_matches(self):
        secrets_content = self._load_secrets()
        
        for pattern in self.patterns:
            self.results[pattern['name']] = set()

        print(colored("Scanning patterns...", 'cyan'))
        for pattern in self.patterns:
            name = pattern['name']
            regex = r'\b' + pattern['regex'] + r'\b'
            try:
                pattern_re = re.compile(regex)
                matches = pattern_re.findall(secrets_content)
                if matches:
                    self.results[name].update(matches)
                    print(colored(f"Found {len(matches)} matches for {name}", 'yellow'))
                else:
                    print(colored(f"No matches for {name}", 'magenta'))
            except re.error:
                print(colored(f"Warning: Invalid regex pattern for {name}: {regex}", 'yellow'))

    def display_results(self, validated_results=None, manual=False, verification_methods=None):
        print(colored("\n=== API Key Search Results ===", 'cyan', attrs=['bold']))
        found_any = False
        
        for name, matches in sorted(self.results.items()):
            if matches:
                found_any = True
                match_count = len(matches)
                print(colored(f"\n{name} (Found: {match_count}):", 'green', attrs=['bold']))
                for match in sorted(matches):
                    if validated_results and match in validated_results:
                        status = validated_results[match]
                        if status is None:
                            print(colored(f"  - {match} [No verification method]", 'yellow'))
                        elif status:
                            print(colored(f"  - {match} ", 'white') + colored("[Valid]", 'green'))
                        else:
                            print(colored(f"  - {match} ", 'white') + colored("[Invalid]", 'red'))
                    else:
                        print(colored(f"  - {match}", 'white'))
                    
                    if manual and verification_methods and name in verification_methods:
                        method = verification_methods[name].replace('$token$', match)
                        if name == "Mailchimp API Key":
                            dc_match = re.search(r'us\d{1,2}$', match)
                            method = method.replace('$dc$', dc_match.group(0) if dc_match else 'us1')
                        print(colored(f"    Manual test: {method}", 'cyan'))

        if not found_any:
            print(colored("No API keys or secrets found matching the specified patterns.", 'yellow'))
        else:
            total_unique = sum(len(matches) for matches in self.results.values())
            print(colored(f"\nTotal unique matches found: {total_unique}", 'cyan'))
        print(colored("==============================", 'cyan', attrs=['bold']))

def load_verification_methods():
    try:
        with open('verification_methods.yaml', 'r') as f:
            data = yaml.safe_load(f)
            return {token['name']: token['verification_method'] for token in data['tokens']}
    except IOError:
        print(colored("Error: Verification methods file not found", 'red'))
        sys.exit(1)
    except yaml.YAMLError:
        print(colored("Error: Invalid YAML in verification methods file", 'red'))
        sys.exit(1)

def validate_token(args):
    token_name, token_value, verification_methods = args
    if token_name not in verification_methods:
        return (token_value, None)
    
    method = verification_methods[token_name]
    if token_name == "Mailchimp API Key":
        dc_match = re.search(r'us\d{1,2}$', token_value)
        if dc_match:
            dc = dc_match.group(0)
            method = method.replace('$dc$', dc)
        else:
            return (token_value, False)
    
    method = method.replace('$token$', token_value)
    try:
        result = subprocess.run(method, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            if token_name == "Heroku API Key":
                # Check for a JSON array of apps (e.g., [{"id": ...}])
                if result.stdout.startswith('[') and '"id"' in result.stdout:
                    return (token_value, True)
                return (token_value, False)
            elif "200" in result.stdout or "id" in result.stdout.lower() or "ok" in result.stdout.lower():
                return (token_value, True)
        return (token_value, False)
    except Exception:
        return (token_value, False)

def validate_all_tokens(results, verification_methods):
    print(colored("\nValidating tokens...", 'cyan'))
    validation_tasks = []
    for name, matches in results.items():
        for match in matches:
            validation_tasks.append((name, match, verification_methods))
    
    with Pool() as pool:
        validated = pool.map(validate_token, validation_tasks)
    
    return dict(validated)

def main():
    parser = argparse.ArgumentParser(
        description="Search for API keys and secrets in a file using regex patterns"
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the secrets file to scan"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate found tokens after scanning"
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Print curl commands for manual testing"
    )
    
    args = parser.parse_args()
    finder = APIFinder(args.file)
    finder.find_matches()
    
    if args.validate or args.manual:
        verification_methods = load_verification_methods()
        if args.validate:
            validated_results = validate_all_tokens(finder.results, verification_methods)
            finder.display_results(validated_results, args.manual, verification_methods)
        else:
            finder.display_results(None, args.manual, verification_methods)
    else:
        finder.display_results()

if __name__ == "__main__":
    try:
        from termcolor import colored
    except ImportError:
        print("Error: Please install termcolor first: 'pip install termcolor'")
        sys.exit(1)
    main()
