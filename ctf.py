import requests
import base64
import binascii
import codecs
from zipfile import ZipFile
import subprocess

# Function to scrape a webpage
def web_scrape(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to retrieve {url}. Status code: {response.status_code}")
        return None

# Function to submit a form
def submit_form(url, data):
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to submit form to {url}. Status code: {response.status_code}")
        return None

# Function to decode Base64
def decode_base64(encoded_str):
    return base64.b64decode(encoded_str).decode('utf-8')

# Function to encode Base64
def encode_base64(decoded_str):
    return base64.b64encode(decoded_str.encode('utf-8')).decode('utf-8')

# Function to decode Hex
def decode_hex(encoded_str):
    return binascii.unhexlify(encoded_str).decode('utf-8')

# Function to encode Hex
def encode_hex(decoded_str):
    return binascii.hexlify(decoded_str.encode('utf-8')).decode('utf-8')

# Function to decode ROT13
def decode_rot13(encoded_str):
    return codecs.decode(encoded_str, 'rot_13')

# Function to encode ROT13
def encode_rot13(decoded_str):
    return codecs.encode(decoded_str, 'rot_13')

# Function to decode Binary
def decode_binary(encoded_str):
    return ''.join([chr(int(b, 2)) for b in encoded_str.split(' ')])

# Function to encode Binary
def encode_binary(decoded_str):
    return ' '.join(format(ord(c), 'b') for c in decoded_str)

# Function to extract files from a ZIP archive
def extract_zip(zip_path, extract_to='.'):
    with ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

# Function to run a shell command
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# Function to run Nmap scan
def run_nmap(target):
    command = f"nmap {target}"
    return run_command(command)

# Function to run Dirb scan
def run_dirb(target, wordlist):
    command = f"dirb {target} {wordlist}"
    return run_command(command)

# Menu function for Encoding & Decoding
def encoding_menu():
    print("Encoding & Decoding")
    print("1. Base64 Encode")
    print("2. Base64 Decode")
    print("3. Hex Encode")
    print("4. Hex Decode")
    print("5. ROT13 Encode")
    print("6. ROT13 Decode")
    print("7. Binary Encode")
    print("8. Binary Decode")
    print("9. Back to Main Menu")

# Menu function for Web tasks
def web_menu():
    print("Web Tasks")
    print("1. Web Scrape")
    print("2. Submit Form")
    print("3. Nmap Scan")
    print("4. Dirb Scan")
    print("5. Back to Main Menu")

# Main Menu function
def menu():
    print("Advanced CTF Helper Script")
    print("1. Encoding & Decoding")
    print("2. Web Tasks")
    print("3. Extract ZIP File")
    print("4. Run Shell Command")
    print("5. Exit")

def main():
    while True:
        menu()
        choice = input("Choose an option: ")

        if choice == '1':
            while True:
                encoding_menu()
                enc_choice = input("Choose an encoding/decoding option: ")
                
                if enc_choice == '1':
                    decoded_str = input("Enter the string to encode in Base64: ")
                    print(encode_base64(decoded_str))
                elif enc_choice == '2':
                    encoded_str = input("Enter the Base64 encoded string: ")
                    print(decode_base64(encoded_str))
                elif enc_choice == '3':
                    decoded_str = input("Enter the string to encode in Hex: ")
                    print(encode_hex(decoded_str))
                elif enc_choice == '4':
                    encoded_str = input("Enter the Hex encoded string: ")
                    print(decode_hex(encoded_str))
                elif enc_choice == '5':
                    decoded_str = input("Enter the string to encode in ROT13: ")
                    print(encode_rot13(decoded_str))
                elif enc_choice == '6':
                    encoded_str = input("Enter the ROT13 encoded string: ")
                    print(decode_rot13(encoded_str))
                elif enc_choice == '7':
                    decoded_str = input("Enter the string to encode in Binary: ")
                    print(encode_binary(decoded_str))
                elif enc_choice == '8':
                    encoded_str = input("Enter the Binary encoded string: ")
                    print(decode_binary(encoded_str))
                elif enc_choice == '9':
                    break
                else:
                    print("Invalid choice, please try again.")

        elif choice == '2':
            while True:
                web_menu()
                web_choice = input("Choose a web task option: ")

                if web_choice == '1':
                    url = input("Enter the URL to scrape: ")
                    content = web_scrape(url)
                    if content:
                        print(content)
                elif web_choice == '2':
                    url = input("Enter the form URL: ")
                    data = {}
                    while True:
                        key = input("Enter form field name (or 'done' to finish): ")
                        if key == 'done':
                            break
                        value = input(f"Enter value for {key}: ")
                        data[key] = value
                    response = submit_form(url, data)
                    if response:
                        print(response)
                elif web_choice == '3':
                    target = input("Enter the target for Nmap scan: ")
                    print(run_nmap(target))
                elif web_choice == '4':
                    target = input("Enter the target URL for Dirb scan: ")
                    wordlist = input("Enter the path to the wordlist: ")
                    print(run_dirb(target, wordlist))
                elif web_choice == '5':
                    break
                else:
                    print("Invalid choice, please try again.")

        elif choice == '3':
            zip_path = input("Enter the path to the ZIP file: ")
            extract_to = input("Enter the directory to extract to (default is current directory): ") or '.'
            extract_zip(zip_path, extract_to)

        elif choice == '4':
            command = input("Enter the shell command to run: ")
            output = run_command(command)
            print(output)

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
