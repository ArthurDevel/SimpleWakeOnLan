import os
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from wakeonlan import send_magic_packet

# --- Configuration ---
DATA_DIR = '/data'  # Persistent volume mount point
MAC_ADDRESSES_FILE = os.path.join(DATA_DIR, 'mac_addresses.json')

app = Flask(__name__)

def ensure_data_dir():
    """Ensure the data directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def load_mac_addresses():
    """Load stored MAC addresses from file."""
    ensure_data_dir()
    try:
        if os.path.exists(MAC_ADDRESSES_FILE):
            with open(MAC_ADDRESSES_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading MAC addresses: {e}")
        return []

def save_mac_addresses(mac_addresses):
    """Save MAC addresses to file."""
    ensure_data_dir()
    try:
        with open(MAC_ADDRESSES_FILE, 'w') as f:
            json.dump(mac_addresses, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving MAC addresses: {e}")
        return False

def add_mac_address(mac_address, device_name=""):
    """Add a new MAC address to storage."""
    mac_addresses = load_mac_addresses()
    
    # Check if MAC already exists
    for entry in mac_addresses:
        if entry['mac'].lower() == mac_address.lower():
            # Update last used time
            entry['last_used'] = datetime.now().isoformat()
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

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/api/wake', methods=['POST'])
def wake_pc():
    """Receives the request and sends the WOL packet."""
    try:
        data = request.get_json()
        if not data or 'mac_address' not in data:
            return jsonify({"status": "error", "message": "MAC address is required."}), 400
            
        mac_address = data['mac_address'].strip()
        device_name = data.get('device_name', '').strip()
        
        if not validate_mac_address(mac_address):
            return jsonify({"status": "error", "message": "Invalid MAC address format."}), 400
        
        # Send the magic packet
        send_magic_packet(mac_address)
        
        # Save/update MAC address in storage
        add_mac_address(mac_address, device_name)
        
        print(f"Sent WOL packet to {mac_address}")
        return jsonify({
            "status": "success", 
            "message": f"Wake-on-LAN packet sent to {mac_address}."
        })
        
    except Exception as e:
        print(f"Error sending WOL packet: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/mac-addresses', methods=['GET'])
def get_mac_addresses():
    """Get all stored MAC addresses."""
    try:
        mac_addresses = load_mac_addresses()
        # Sort by last used (most recent first)
        mac_addresses.sort(key=lambda x: x['last_used'], reverse=True)
        return jsonify({"status": "success", "mac_addresses": mac_addresses})
    except Exception as e:
        print(f"Error retrieving MAC addresses: {e}")
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
        print(f"Error deleting MAC address: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

if __name__ == '__main__':
    # Use 0.0.0.0 to be accessible within the Docker network
    app.run(host='0.0.0.0', port=8000, debug=True)
