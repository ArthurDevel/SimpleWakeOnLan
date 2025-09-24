# Simple Wake-on-LAN Controller

A simple web interface for sending Wake-on-LAN packets to wake up devices on your network. Designed to run on a Raspberry Pi and work with Cloudflare Zero Trust tunnel to create an easy remote wake button for your PC. Once your PC is awake, you can use Parsec or TeamViewer to remotely access it.

## Prerequisites

### Target Device Setup

Before using this controller, ensure your target devices are properly configured:

1. **BIOS/UEFI Settings**:
   - Enter BIOS/UEFI (usually DEL, F2, or F12 during boot)
   - Enable "Wake on LAN" or "Power On by PCI-E"
   - Save and exit

2. **Operating System Setup**:
   - **Windows**: Device Manager → Network Adapter → Properties → Power Management → Enable "Allow this device to wake the computer"
   - **Linux**: Check with `ethtool eth0` and enable with `sudo ethtool -s eth0 wol g`

3. **Network Requirements**:
   - Target device must be connected via Ethernet (Wi-Fi WOL is unreliable)
   - Device must be on the same network or VLAN
   - Find MAC address: `ipconfig /all` (Windows) or `ifconfig` (Linux/macOS)

## Deployment

### Docker Compose (Recommended)

Use Docker Compose when you want persistent storage for your MAC addresses between container restarts:

```bash
docker-compose up -d
```

Access the web interface at `http://your-server-ip:8000`

### Docker Only

Use plain Docker for testing or when you don't need persistent storage:

```bash
docker build -t wake-on-lan .
docker run -p 8000:8000 wake-on-lan
```

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

