import os
import json
import logging
import subprocess
import base64
import socket
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import paramiko

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration ---
DATA_DIR = '/data'  # Persistent volume mount point
MAC_ADDRESSES_FILE = os.path.join(DATA_DIR, 'mac_addresses.json')
ENCRYPTION_KEY_FILE = os.path.join(DATA_DIR, 'encryption.key')

app = Flask(__name__)

def ensure_data_dir():
    """Ensure the data directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def get_encryption_key():
    """Get or create encryption key for securing SSH passwords."""
    ensure_data_dir()
    try:
        if os.path.exists(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            return key
    except Exception as e:
        logger.error(f"Error handling encryption key: {e}")
        raise

def encrypt_password(password):
    """Encrypt a password for secure storage."""
    if not password:
        return None
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Error encrypting password: {e}")
        return None

def decrypt_password(encrypted_password):
    """Decrypt a stored password."""
    if not encrypted_password:
        return None
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        return f.decrypt(encrypted_bytes).decode()
    except Exception as e:
        logger.error(f"Error decrypting password: {e}")
        return None

def load_mac_addresses():
    """Load stored MAC addresses from file."""
    ensure_data_dir()
    try:
        if os.path.exists(MAC_ADDRESSES_FILE):
            with open(MAC_ADDRESSES_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Error loading MAC addresses: {e}")
        return []

def save_mac_addresses(mac_addresses):
    """Save MAC addresses to file."""
    ensure_data_dir()
    try:
        with open(MAC_ADDRESSES_FILE, 'w') as f:
            json.dump(mac_addresses, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving MAC addresses: {e}")
        return False

def add_mac_address(mac_address, device_name=""):
    """Add a new MAC address to storage."""
    mac_addresses = load_mac_addresses()
    
    # Check if MAC already exists
    for entry in mac_addresses:
        if entry['mac'].lower() == mac_address.lower():
            # Update last used time
            entry['last_used'] = datetime.now().isoformat()
            entry['usage_count'] = entry.get('usage_count', 0) + 1
            save_mac_addresses(mac_addresses)
            return True
    
    # Add new MAC address
    new_entry = {
        'mac': mac_address.upper(),
        'device_name': device_name or f"Device {len(mac_addresses) + 1}",
        'added_date': datetime.now().isoformat(),
        'last_used': datetime.now().isoformat(),
        'usage_count': 1
    }
    
    mac_addresses.append(new_entry)
    return save_mac_addresses(mac_addresses)

def validate_mac_address(mac):
    """Validate MAC address format."""
    import re
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))

def validate_ip_address(ip):
    """Validate IP address format."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def discover_ip_from_mac(mac_address):
    """Try to discover IP address from MAC address using ARP table."""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if mac_address.lower().replace('-', ':') in line.lower():
                # Extract IP from ARP entry
                import re
                ip_match = re.search(r'\((.*?)\)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if validate_ip_address(ip):
                        return ip
    except Exception as e:
        logger.warning(f"Could not discover IP from MAC {mac_address}: {e}")
    return None

def execute_ssh_shutdown(ip_address, username, password, port=22):
    """Execute shutdown command via SSH."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the remote host
        ssh.connect(ip_address, port=port, username=username, password=password, timeout=10)
        
        # Determine the appropriate shutdown command based on the system
        # Try Windows forced shutdown commands first, then Linux alternatives
        commands = [
            # Windows forced shutdown commands (highest priority)
            'shutdown /s /f /t 0',                          # Windows forced shutdown
            'wmic os where Primary=TRUE call Shutdown',     # WMI forced shutdown
            'powershell "Stop-Computer -Force"',            # PowerShell forced shutdown
            
            # Linux commands without sudo (for systems where sudo is disabled)
            'systemctl poweroff --force --force',           # SystemD double-force without sudo
            'poweroff --force',                             # Force poweroff without sudo
            'halt --force',                                 # Force halt without sudo
            
            # Linux commands with sudo (if available)
            'sudo systemctl poweroff --force --force',      # SystemD double-force with sudo
            'sudo poweroff --force',                        # Force poweroff with sudo
            'sudo halt --force',                            # Force halt with sudo
            
            # Magic SysRq trigger (Linux kernel level emergency)
            'echo 1 | tee /proc/sys/kernel/sysrq > /dev/null 2>&1 && echo o | tee /proc/sysrq-trigger > /dev/null 2>&1',
            'echo 1 | sudo tee /proc/sys/kernel/sysrq > /dev/null 2>&1 && echo o | sudo tee /proc/sysrq-trigger > /dev/null 2>&1',
            
            # Fallback graceful commands
            'shutdown /s /t 0',           # Windows graceful shutdown
            'shutdown -h now',            # Linux graceful without sudo
            'sudo shutdown -h now',       # Linux graceful with sudo
            'poweroff',                   # Basic Linux poweroff
        ]
        
        for cmd in commands:
            try:
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
                # Don't wait for output as the connection will likely drop
                logger.info(f"Executed shutdown command: {cmd}")
                break
            except Exception as e:
                logger.warning(f"Command '{cmd}' failed: {e}")
                continue
        
        ssh.close()
        return True, "Shutdown command sent successfully"
        
    except paramiko.AuthenticationException:
        return False, "Authentication failed - check username and password"
    except paramiko.SSHException as e:
        return False, f"SSH connection error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/api/wake', methods=['POST'])
def wake_pc():
    """Receives the request and sends the WOL packet."""
    logger.info("=== WOL REQUEST RECEIVED ===")
    try:
        data = request.get_json()
        logger.info(f"Request data: {data}")
        if not data or 'mac_address' not in data:
            return jsonify({"status": "error", "message": "MAC address is required."}), 400
            
        mac_address = data['mac_address'].strip()
        device_name = data.get('device_name', '').strip()
        
        if not validate_mac_address(mac_address):
            return jsonify({"status": "error", "message": "Invalid MAC address format."}), 400
        
        # Send the magic packet by calling the system's wakeonlan command
        logger.info(f"Sending WOL packet to MAC: {mac_address} using command-line tool")
        
        try:
            # The command will automatically find the correct broadcast interface
            completed_process = subprocess.run(
                ["wakeonlan", mac_address],
                capture_output=True,
                text=True,
                check=True  # This will raise an exception if the command fails
            )
            logger.info(f"wakeonlan stdout: {completed_process.stdout.strip()}")
            logger.info(f"wakeonlan stderr: {completed_process.stderr.strip()}")
        except FileNotFoundError:
            logger.error("The 'wakeonlan' command was not found in the container.")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"The 'wakeonlan' command failed with exit code {e.returncode}")
            logger.error(f"Stderr: {e.stderr.strip()}")
            raise
        
        # Save/update MAC address in storage
        add_mac_address(mac_address, device_name)
        
        logger.info(f"=== SUCCESS: Sent WOL packet to {mac_address} ===")
        return jsonify({
            "status": "success", 
            "message": f"Wake-on-LAN packet sent to {mac_address}."
        })
        
    except Exception as e:
        logger.error(f"=== ERROR: Failed to send WOL packet: {e} ===")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/shutdown', methods=['POST'])
def shutdown_pc():
    """Shutdown a device via SSH."""
    logger.info("=== SHUTDOWN REQUEST RECEIVED ===")
    try:
        data = request.get_json()
        logger.info(f"Request data: {data}")
        if not data or 'mac_address' not in data:
            return jsonify({"status": "error", "message": "MAC address is required."}), 400
            
        mac_address = data['mac_address'].strip()
        
        if not validate_mac_address(mac_address):
            return jsonify({"status": "error", "message": "Invalid MAC address format."}), 400
        
        # Check if temporary SSH credentials are provided
        temp_ssh_creds = data.get('temp_ssh_credentials')
        save_ssh_credentials = data.get('save_ssh_credentials', False)
        
        if temp_ssh_creds:
            # Use temporary credentials for shutdown (new modal flow)
            ip_address = temp_ssh_creds.get('ip_address', '').strip()
            username = temp_ssh_creds.get('username', '').strip()
            password = temp_ssh_creds.get('password', '').strip()
            port = temp_ssh_creds.get('port', 22)
            
            if not ip_address or not username or not password:
                return jsonify({"status": "error", "message": "Incomplete SSH credentials."}), 400
                
        else:
            # Legacy flow: use stored credentials
            mac_addresses = load_mac_addresses()
            device = None
            for entry in mac_addresses:
                if entry['mac'].lower() == mac_address.lower():
                    device = entry
                    break
                    
            if not device:
                return jsonify({"status": "error", "message": "Device not found in storage."}), 404
                
            if not device.get('ssh_enabled', False):
                return jsonify({"status": "error", "message": "SSH not configured for this device."}), 400
                
            # Get SSH credentials from storage
            ip_address = device.get('ip_address', '')
            username = device.get('ssh_username', '')
            encrypted_password = device.get('ssh_password', '')
            port = device.get('ssh_port', 22)
            
            if not ip_address or not username or not encrypted_password:
                return jsonify({"status": "error", "message": "Incomplete SSH credentials."}), 400
                
            # Decrypt password
            password = decrypt_password(encrypted_password)
            if not password:
                return jsonify({"status": "error", "message": "Failed to decrypt password."}), 500
            
        # Execute shutdown
        logger.info(f"Attempting to shutdown device at {ip_address}")
        success, message = execute_ssh_shutdown(ip_address, username, password, port)
        
        if success:
            # Update last used time for the device if it exists in storage
            # Also save SSH credentials if requested
            mac_addresses = load_mac_addresses()
            for entry in mac_addresses:
                if entry['mac'].lower() == mac_address.lower():
                    entry['last_used'] = datetime.now().isoformat()
                    
                    # Save SSH credentials if requested and using temp credentials
                    if save_ssh_credentials and temp_ssh_creds:
                        entry['ssh_enabled'] = True
                        entry['ip_address'] = ip_address
                        entry['ssh_username'] = username
                        entry['ssh_password'] = encrypt_password(password)
                        entry['ssh_port'] = port
                    
                    save_mac_addresses(mac_addresses)
                    break
            
            logger.info(f"=== SUCCESS: Shutdown command sent to {ip_address} ===")
            return jsonify({
                "status": "success", 
                "message": f"Shutdown command sent to device {mac_address}."
            })
        else:
            logger.error(f"=== ERROR: Failed to shutdown {ip_address}: {message} ===")
            return jsonify({"status": "error", "message": message}), 500
        
    except Exception as e:
        logger.error(f"=== ERROR: Failed to send shutdown command: {e} ===")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/discover-ip', methods=['POST'])
def discover_ip():
    """Try to discover IP address from MAC address."""
    try:
        data = request.get_json()
        if not data or 'mac_address' not in data:
            return jsonify({"status": "error", "message": "MAC address is required."}), 400
            
        mac_address = data['mac_address'].strip()
        
        if not validate_mac_address(mac_address):
            return jsonify({"status": "error", "message": "Invalid MAC address format."}), 400
        
        discovered_ip = discover_ip_from_mac(mac_address)
        
        if discovered_ip:
            return jsonify({
                "status": "success", 
                "ip_address": discovered_ip,
                "message": f"Found IP {discovered_ip} for MAC {mac_address}"
            })
        else:
            return jsonify({
                "status": "error", 
                "message": "Could not discover IP address. Device may be offline or not in ARP table."
            }), 404
        
    except Exception as e:
        logger.error(f"Error discovering IP: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/mac-addresses', methods=['GET'])
def get_mac_addresses():
    """Get all stored MAC addresses."""
    try:
        mac_addresses = load_mac_addresses()
        # Sort by last used (most recent first)
        mac_addresses.sort(key=lambda x: x['last_used'], reverse=True)
        
        # Remove encrypted passwords from response for security, but keep other SSH info
        safe_addresses = []
        for addr in mac_addresses:
            safe_addr = addr.copy()
            # Don't include the encrypted password in API responses
            if 'ssh_password' in safe_addr:
                safe_addr['ssh_password'] = '***' if safe_addr['ssh_password'] else None
            safe_addresses.append(safe_addr)
            
        return jsonify({"status": "success", "mac_addresses": safe_addresses})
    except Exception as e:
        logger.error(f"Error retrieving MAC addresses: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/mac-addresses/<mac_address>', methods=['DELETE'])
def delete_mac_address(mac_address):
    """Delete a stored MAC address."""
    try:
        mac_addresses = load_mac_addresses()
        mac_addresses = [entry for entry in mac_addresses if entry['mac'].lower() != mac_address.lower()]
        
        if save_mac_addresses(mac_addresses):
            return jsonify({"status": "success", "message": "MAC address deleted."})
        else:
            return jsonify({"status": "error", "message": "Failed to save changes."}), 500
            
    except Exception as e:
        logger.error(f"Error deleting MAC address: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

if __name__ == '__main__':
    # Use 0.0.0.0 to be accessible within the Docker network
    app.run(host='0.0.0.0', port=8000, debug=True)
