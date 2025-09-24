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
   - **Windows**: 
     - Device Manager → Network Adapter → Properties → Power Management → Enable "Allow this device to wake the computer"
     - Device Manager → Network Adapter → Properties → Advanced → Disable "Energy Efficient Ethernet"
     - Control Panel → Power Options → Choose what the power buttons do → Change settings that are currently unavailable → Disable "Turn on fast startup"
   - **Linux**: Check with `ethtool eth0` and enable with `sudo ethtool -s eth0 wol g`

3. **Network Requirements**:
   - Target device must be connected via Ethernet (Wi-Fi WOL is unreliable)
   - Device must be on the same network or VLAN
   - Find MAC address: `ipconfig /all` (Windows) or `ifconfig` (Linux/macOS)

## Deployment

### Docker Compose (Recommended for Raspberry Pi / Linux)

This method is ideal for deployment on a Raspberry Pi or any Linux-based host. It uses `network_mode: host` to give the container direct access to your physical network, which is the most reliable way to ensure Wake-on-LAN packets are delivered.

```bash
docker-compose up -d
```

Access the web interface at `http://your-server-ip:8000`

### Docker Only (Recommended for Raspberry Pi / Linux)

This is the equivalent plain Docker command for a Linux-based host.

```bash
docker build -t wake-on-lan .
docker run --network host wake-on-lan
```

### A Note on macOS Development

The `network_mode: host` setting does **not** work on Docker for Mac as it does on Linux. On a Mac, the container's network is attached to a hidden Virtual Machine, not your physical LAN. Therefore, while the container will build and run on your Mac, the Wake-on-LAN packet will not reach your PC.

**This project is intended for deployment on a Linux host like a Raspberry Pi, where it will function correctly.**

## License

This project is open source and available under the MIT License.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

