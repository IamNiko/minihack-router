#!/usr/bin/env python3
"""
🚀 Enhanced Router Dashboard - Device Control & Authentication
Ultra-optimized monitoring system with device management
Features: Device Control, Parental Controls, User Authentication
Author: The Universe's Best Developer 🌟
"""

import os
import sys
import json
import time
import psutil
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
import logging
import socket
import hashlib
import secrets
from functools import wraps

# Configure professional logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dashboard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DeviceManager:
    """Device management and control system"""
    
    def __init__(self):
        self.devices_db_file = 'devices_config.json'
        self.blocked_devices = set()
        self.device_schedules = {}
        self.content_filters = {}
        self.load_device_config()
    
    def load_device_config(self):
        """Load device configuration from file"""
        try:
            if os.path.exists(self.devices_db_file):
                with open(self.devices_db_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_devices = set(data.get('blocked_devices', []))
                    self.device_schedules = data.get('device_schedules', {})
                    self.content_filters = data.get('content_filters', {})
                logger.info(f"Loaded device config: {len(self.blocked_devices)} blocked devices")
            else:
                self.save_device_config()
        except Exception as e:
            logger.error(f"Error loading device config: {e}")
    
    def save_device_config(self):
        """Save device configuration to file"""
        try:
            data = {
                'blocked_devices': list(self.blocked_devices),
                'device_schedules': self.device_schedules,
                'content_filters': self.content_filters,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.devices_db_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Device configuration saved")
        except Exception as e:
            logger.error(f"Error saving device config: {e}")
    
    def block_device(self, mac_address, reason="Manual block"):
        """Block internet access for a device"""
        try:
            mac_address = mac_address.lower()
            
            # Add to blocked list
            self.blocked_devices.add(mac_address)
            
            # Apply iptables rule to block device
            self._apply_device_block(mac_address, block=True)
            
            self.save_device_config()
            logger.info(f"Device {mac_address} blocked: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error blocking device {mac_address}: {e}")
            return False
    
    def unblock_device(self, mac_address):
        """Unblock internet access for a device"""
        try:
            mac_address = mac_address.lower()
            
            # Remove from blocked list
            self.blocked_devices.discard(mac_address)
            
            # Remove iptables rule
            self._apply_device_block(mac_address, block=False)
            
            self.save_device_config()
            logger.info(f"Device {mac_address} unblocked")
            return True
        except Exception as e:
            logger.error(f"Error unblocking device {mac_address}: {e}")
            return False
    
    def _apply_device_block(self, mac_address, block=True):
        """Apply or remove iptables rules for device blocking"""
        try:
            action = "DROP" if block else "ACCEPT"
            
            # Block outgoing traffic from device
            rule_out = f"iptables -t filter -{'A' if block else 'D'} FORWARD -m mac --mac-source {mac_address} -j {action}"
            
            # Block incoming traffic to device  
            rule_in = f"iptables -t filter -{'A' if block else 'D'} FORWARD -m mac --mac-destination {mac_address} -j {action}"
            
            if not block:
                # When unblocking, first try to delete existing rules
                rule_out = rule_out.replace('-A', '-D')
                rule_in = rule_in.replace('-A', '-D')
            
            # Execute iptables commands
            subprocess.run(rule_out.split(), check=False)
            subprocess.run(rule_in.split(), check=False)
            
            logger.info(f"Applied iptables rules for {mac_address}: {'blocked' if block else 'unblocked'}")
            
        except Exception as e:
            logger.error(f"Error applying iptables rules for {mac_address}: {e}")
    
    def set_device_schedule(self, mac_address, schedule_config):
        """Set internet access schedule for a device"""
        try:
            mac_address = mac_address.lower()
            self.device_schedules[mac_address] = schedule_config
            self.save_device_config()
            logger.info(f"Schedule set for device {mac_address}")
            return True
        except Exception as e:
            logger.error(f"Error setting schedule for {mac_address}: {e}")
            return False
    
    def set_content_filter(self, mac_address, filter_config):
        """Set content filtering for a device"""
        try:
            mac_address = mac_address.lower()
            self.content_filters[mac_address] = filter_config
            
            # Apply DNS filtering rules
            self._apply_content_filter(mac_address, filter_config)
            
            self.save_device_config()
            logger.info(f"Content filter set for device {mac_address}")
            return True
        except Exception as e:
            logger.error(f"Error setting content filter for {mac_address}: {e}")
            return False
    
    def _apply_content_filter(self, mac_address, filter_config):
        """Apply DNS-based content filtering"""
        try:
            # Configure DNS filtering based on categories
            blocked_categories = filter_config.get('blocked_categories', [])
            
            dns_servers = {
                'adult_content': ['208.67.222.123', '208.67.220.123'],  # OpenDNS FamilyShield
                'malware': ['1.1.1.2', '1.0.0.2'],  # Cloudflare for Families
                'ads': ['176.103.130.130', '176.103.130.131'],  # AdGuard DNS
                'default': ['8.8.8.8', '8.8.4.4']  # Google DNS
            }
            
            # Select appropriate DNS based on filtering needs
            if 'adult_content' in blocked_categories or 'violence' in blocked_categories:
                selected_dns = dns_servers['adult_content']
            elif 'malware' in blocked_categories:
                selected_dns = dns_servers['malware']
            elif 'ads' in blocked_categories:
                selected_dns = dns_servers['ads']
            else:
                selected_dns = dns_servers['default']
            
            # Apply DNS redirect rules for the specific device
            for dns_ip in selected_dns:
                rule = f"iptables -t nat -A PREROUTING -m mac --mac-source {mac_address} -p udp --dport 53 -j DNAT --to-destination {dns_ip}:53"
                subprocess.run(rule.split(), check=False)
            
            logger.info(f"Content filter applied for {mac_address}: {blocked_categories}")
            
        except Exception as e:
            logger.error(f"Error applying content filter for {mac_address}: {e}")
    
    def check_device_schedule(self, mac_address):
        """Check if device should be blocked based on schedule"""
        try:
            mac_address = mac_address.lower()
            if mac_address not in self.device_schedules:
                return False  # No schedule = no restrictions
            
            schedule = self.device_schedules[mac_address]
            current_time = datetime.now()
            current_day = current_time.strftime('%A').lower()
            current_hour = current_time.hour
            current_minute = current_time.minute
            current_minutes = current_hour * 60 + current_minute
            
            # Check daily schedule
            daily_schedule = schedule.get('daily_hours', {})
            if daily_schedule.get('enabled', False):
                start_time = daily_schedule.get('start_time', '00:00')
                end_time = daily_schedule.get('end_time', '23:59')
                
                start_minutes = self._time_to_minutes(start_time)
                end_minutes = self._time_to_minutes(end_time)
                
                # Check if current time is outside allowed hours
                if not (start_minutes <= current_minutes <= end_minutes):
                    return True  # Should be blocked
            
            # Check weekly schedule
            weekly_schedule = schedule.get('weekly_schedule', {})
            if weekly_schedule.get('enabled', False):
                day_config = weekly_schedule.get(current_day, {})
                if day_config.get('blocked', False):
                    return True  # Day is blocked
                
                if day_config.get('time_limit_enabled', False):
                    # Check time limits (would need usage tracking)
                    pass
            
            return False  # Not blocked
            
        except Exception as e:
            logger.error(f"Error checking schedule for {mac_address}: {e}")
            return False
    
    def _time_to_minutes(self, time_str):
        """Convert time string (HH:MM) to minutes since midnight"""
        try:
            hours, minutes = map(int, time_str.split(':'))
            return hours * 60 + minutes
        except:
            return 0
    
    def get_device_info(self, mac_address):
        """Get complete device information and settings"""
        mac_address = mac_address.lower()
        return {
            'mac_address': mac_address,
            'is_blocked': mac_address in self.blocked_devices,
            'schedule': self.device_schedules.get(mac_address, {}),
            'content_filter': self.content_filters.get(mac_address, {}),
            'scheduled_block': self.check_device_schedule(mac_address)
        }

class AuthManager:
    """Authentication and user management system"""
    
    def __init__(self):
        self.users_db_file = 'users_config.json'
        self.users = {}
        self.sessions = {}
        self.load_users()
    
    def load_users(self):
        """Load users from file"""
        try:
            if os.path.exists(self.users_db_file):
                with open(self.users_db_file, 'r') as f:
                    self.users = json.load(f)
                logger.info(f"Loaded {len(self.users)} users")
            else:
                # Create default admin user
                self.create_default_admin()
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            self.create_default_admin()
    
    def create_default_admin(self):
        """Create default admin user"""
        default_password = "admin123"  # Should be changed on first login
        self.users = {
            'admin': {
                'password_hash': self._hash_password(default_password),
                'role': 'admin',
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'must_change_password': True
            }
        }
        self.save_users()
        logger.warning(f"Created default admin user with password: {default_password}")
    
    def save_users(self):
        """Save users to file"""
        try:
            with open(self.users_db_file, 'w') as f:
                json.dump(self.users, f, indent=2)
            logger.info("Users configuration saved")
        except Exception as e:
            logger.error(f"Error saving users: {e}")
    
    def _hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username, password):
        """Authenticate user"""
        try:
            if username not in self.users:
                return False, "Usuario no encontrado"
            
            user = self.users[username]
            password_hash = self._hash_password(password)
            
            if user['password_hash'] != password_hash:
                return False, "Contraseña incorrecta"
            
            # Update last login
            self.users[username]['last_login'] = datetime.now().isoformat()
            self.save_users()
            
            return True, "Login exitoso"
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, "Error de autenticación"
    
    def create_user(self, username, password, role='user'):
        """Create new user"""
        try:
            if username in self.users:
                return False, "Usuario ya existe"
            
            self.users[username] = {
                'password_hash': self._hash_password(password),
                'role': role,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'must_change_password': False
            }
            
            self.save_users()
            logger.info(f"User created: {username} ({role})")
            return True, "Usuario creado exitosamente"
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False, "Error creando usuario"
    
    def change_password(self, username, old_password, new_password):
        """Change user password"""
        try:
            if username not in self.users:
                return False, "Usuario no encontrado"
            
            # Verify old password
            if self._hash_password(old_password) != self.users[username]['password_hash']:
                return False, "Contraseña actual incorrecta"
            
            # Update password
            self.users[username]['password_hash'] = self._hash_password(new_password)
            self.users[username]['must_change_password'] = False
            self.save_users()
            
            logger.info(f"Password changed for user: {username}")
            return True, "Contraseña cambiada exitosamente"
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False, "Error cambiando contraseña"

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if session.get('user', {}).get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

class EnhancedRouterDashboard:
    """Enhanced Router Dashboard with device control and authentication"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = secrets.token_hex(32)  # Random secret key
        CORS(self.app, origins=['*'], supports_credentials=True)
        
        # Initialize managers
        self.device_manager = DeviceManager()
        self.auth_manager = AuthManager()
        
        # System metrics cache (from original dashboard)
        self.cache = {
            'system': None,
            'wifi_devices': [],
            'connections': [],
            'interfaces': {},
            'suricata_alerts': [],
            'port_scans': [],
            'last_update': None
        }
        
        # Historical data
        self.historical_data = {
            'cpu': deque(maxlen=100),
            'memory': deque(maxlen=100), 
            'network_in': deque(maxlen=100),
            'network_out': deque(maxlen=100),
            'timestamps': deque(maxlen=100),
            'temperature': deque(maxlen=100)
        }
        
        # Performance monitoring
        self.stats = {
            'requests_served': 0,
            'cache_hits': 0,
            'errors': 0,
            'uptime_start': datetime.now(),
            'clients_connected': set()
        }
        
        # Thread control
        self.monitoring_active = True
        self.lock = threading.RLock()
        
        self._setup_routes()
        logger.info("🚀 Enhanced Router Dashboard initialized with authentication and device control")
    
    # Include all original system monitoring methods here
    def get_system_info(self):
        """Get comprehensive system information with error handling"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_temp = self._get_cpu_temperature()
            cpu_count = psutil.cpu_count()
            load_avg = os.getloadavg()
            
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            net_io = psutil.net_io_counters()
            process_count = len(psutil.pids())
            
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            return {
                'cpu': {
                    'percent': round(cpu_percent, 1),
                    'temperature': cpu_temp,
                    'cores': cpu_count,
                    'load_avg': {
                        '1min': round(load_avg[0], 2),
                        '5min': round(load_avg[1], 2),
                        '15min': round(load_avg[2], 2)
                    }
                },
                'memory': {
                    'percent': round(memory.percent, 1),
                    'total': memory.total,
                    'used': memory.used,
                    'available': memory.available,
                    'free': memory.free,
                    'buffers': getattr(memory, 'buffers', 0),
                    'cached': getattr(memory, 'cached', 0)
                },
                'swap': {
                    'percent': round(swap.percent, 1),
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free
                },
                'disk': {
                    'percent': round(disk.percent, 1),
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'io': {
                        'read_bytes': disk_io.read_bytes if disk_io else 0,
                        'write_bytes': disk_io.write_bytes if disk_io else 0,
                        'read_count': disk_io.read_count if disk_io else 0,
                        'write_count': disk_io.write_count if disk_io else 0
                    }
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errin': net_io.errin,
                    'errout': net_io.errout,
                    'dropin': net_io.dropin,
                    'dropout': net_io.dropout
                },
                'system': {
                    'processes': process_count,
                    'uptime_seconds': int(uptime.total_seconds()),
                    'uptime_formatted': str(uptime).split('.')[0],
                    'boot_time': boot_time.isoformat()
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return None
    
    def _get_cpu_temperature(self):
        """Get CPU temperature with multiple fallback methods"""
        try:
            if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp = float(f.read().strip()) / 1000
                return round(temp, 1)
        except:
            pass
        
        try:
            result = subprocess.run(['sensors'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'temp' in line.lower() and '°C' in line:
                    temp_str = line.split('°C')[0].split()[-1]
                    return round(float(temp_str.replace('+', '')), 1)
        except:
            pass
        
        return 0
    
    def get_wifi_devices(self):
        """Get connected WiFi devices with enhanced info"""
        try:
            result = subprocess.run(['iw', 'dev', 'wlan0', 'station', 'dump'], 
                                  capture_output=True, text=True, timeout=5)
            
            devices = []
            current_device = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Station'):
                    if current_device:
                        # Add device control info
                        mac = current_device['mac'].lower()
                        device_info = self.device_manager.get_device_info(mac)
                        current_device.update(device_info)
                        devices.append(current_device)
                    
                    mac = line.split()[1]
                    current_device = {
                        'mac': mac,
                        'signal': 'N/A',
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                        'rx_packets': 0,
                        'tx_packets': 0,
                        'connected_time': 'Unknown'
                    }
                elif 'signal:' in line:
                    signal = line.split('signal:')[1].strip().split()[0]
                    current_device['signal'] = signal
                elif 'rx bytes:' in line:
                    rx_bytes = line.split('rx bytes:')[1].strip()
                    current_device['rx_bytes'] = int(rx_bytes)
                elif 'tx bytes:' in line:
                    tx_bytes = line.split('tx bytes:')[1].strip()
                    current_device['tx_bytes'] = int(tx_bytes)
                elif 'rx packets:' in line:
                    rx_packets = line.split('rx packets:')[1].strip()
                    current_device['rx_packets'] = int(rx_packets)
                elif 'tx packets:' in line:
                    tx_packets = line.split('tx packets:')[1].strip()
                    current_device['tx_packets'] = int(tx_packets)
                elif 'connected time:' in line:
                    connected_time = line.split('connected time:')[1].strip()
                    current_device['connected_time'] = connected_time
            
            if current_device:
                mac = current_device['mac'].lower()
                device_info = self.device_manager.get_device_info(mac)
                current_device.update(device_info)
                devices.append(current_device)
            
            return devices
            
        except Exception as e:
            logger.error(f"Error getting WiFi devices: {e}")
            return []
    
    def get_network_connections(self):
        """Get network connections with enhanced filtering"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in ['ESTABLISHED', 'LISTEN']:
                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else 'Unknown'
                    except:
                        process_name = 'Unknown'
                    
                    connections.append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid,
                        'process': process_name,
                        'family': 'IPv4' if conn.family.name == 'AF_INET' else 'IPv6'
                    })
            
            return sorted(connections, key=lambda x: x['status'])
            
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
            return []
    
    def get_interface_stats(self):
        """Get detailed network interface statistics"""
        try:
            interfaces = {}
            for interface, stats in psutil.net_io_counters(pernic=True).items():
                # Get interface status
                try:
                    with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                        status = f.read().strip()
                except:
                    status = 'unknown'
                
                interfaces[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout,
                    'status': status
                }
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting interface stats: {e}")
            return {}
    
    def get_suricata_alerts(self):
        """Get Suricata IDS alerts with intelligent parsing"""
        try:
            alerts = []
            log_files = [
                '/var/log/suricata/eve.json',
                '/var/log/suricata/fast.log'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r') as f:
                            lines = f.readlines()[-20:]  # Last 20 lines
                            for line in lines:
                                try:
                                    if log_file.endswith('.json'):
                                        data = json.loads(line.strip())
                                        if data.get('event_type') == 'alert':
                                            alerts.append({
                                                'timestamp': data['timestamp'],
                                                'alert': data['alert'],
                                                'src_ip': data.get('src_ip', 'N/A'),
                                                'dest_ip': data.get('dest_ip', 'N/A'),
                                                'proto': data.get('proto', 'N/A'),
                                                'severity': data.get('alert', {}).get('severity', 3)
                                            })
                                except json.JSONDecodeError:
                                    continue
                        break  # Use first available log file
                    except Exception as e:
                        logger.warning(f"Error reading {log_file}: {e}")
                        continue
            
            return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:10]
            
        except Exception as e:
            logger.error(f"Error getting Suricata alerts: {e}")
            return []
    
    def get_port_scan_detection(self):
        """Advanced port scan detection with heuristics"""
        try:
            connections = psutil.net_connections()
            ip_analysis = defaultdict(lambda: {
                'ports': set(),
                'connections': 0,
                'first_seen': datetime.now(),
                'protocols': set()
            })
            
            # Analyze connections
            for conn in connections:
                if conn.raddr and conn.status in ['SYN_SENT', 'SYN_RECV', 'ESTABLISHED']:
                    ip = conn.raddr.ip
                    ip_analysis[ip]['ports'].add(conn.raddr.port)
                    ip_analysis[ip]['connections'] += 1
                    ip_analysis[ip]['protocols'].add(conn.type.name)
            
            # Detect suspicious patterns
            suspicious_ips = []
            for ip, data in ip_analysis.items():
                port_count = len(data['ports'])
                connection_count = data['connections']
                
                # Heuristics for port scanning
                if (port_count > 10 or 
                    connection_count > 20 or 
                    (port_count > 5 and connection_count > port_count * 2)):
                    
                    risk_score = min(100, (port_count * 5) + (connection_count * 2))
                    
                    suspicious_ips.append({
                        'ip': ip,
                        'ports_count': port_count,
                        'connections_count': connection_count,
                        'ports': sorted(list(data['ports']))[:15],  # Show first 15
                        'protocols': list(data['protocols']),
                        'risk_score': risk_score,
                        'threat_level': 'HIGH' if risk_score > 70 else 'MEDIUM' if risk_score > 40 else 'LOW'
                    })
            
            return sorted(suspicious_ips, key=lambda x: x['risk_score'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error detecting port scans: {e}")
            return []
    
    def update_cache(self):
        """Update system cache with fresh data"""
        try:
            with self.lock:
                logger.debug("Updating system cache...")
                
                system_info = self.get_system_info()
                if system_info:
                    self.cache['system'] = system_info
                    
                    now = datetime.now()
                    self.historical_data['cpu'].append(system_info['cpu']['percent'])
                    self.historical_data['memory'].append(system_info['memory']['percent'])
                    self.historical_data['network_in'].append(system_info['network']['bytes_recv'])
                    self.historical_data['network_out'].append(system_info['network']['bytes_sent'])
                    self.historical_data['temperature'].append(system_info['cpu']['temperature'])
                    self.historical_data['timestamps'].append(now.strftime('%H:%M:%S'))
                
                if len(self.historical_data['timestamps']) % 3 == 0:
                    self.cache['wifi_devices'] = self.get_wifi_devices()
                    self.cache['connections'] = self.get_network_connections()
                    self.cache['interfaces'] = self.get_interface_stats()
                    self.cache['suricata_alerts'] = self.get_suricata_alerts()
                    self.cache['port_scans'] = self.get_port_scan_detection()
                
                self.cache['last_update'] = datetime.now().isoformat()
                logger.debug("Cache updated successfully")
                
        except Exception as e:
            logger.error(f"Error updating cache: {e}")
            self.stats['errors'] += 1
    
    def monitoring_loop(self):
        """Background monitoring loop"""
        logger.info("🔄 Starting background monitoring loop")
        
        while self.monitoring_active:
            try:
                start_time = time.time()
                self.update_cache()
                
                cpu_percent = self.cache.get('system', {}).get('cpu', {}).get('percent', 0)
                if cpu_percent > 80:
                    sleep_time = 3
                elif cpu_percent > 50:
                    sleep_time = 2
                else:
                    sleep_time = 1
                
                elapsed = time.time() - start_time
                actual_sleep = max(0.1, sleep_time - elapsed)
                time.sleep(actual_sleep)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self.stats['errors'] += 1
                time.sleep(5)
    
    def _setup_routes(self):
        """Setup all Flask routes including new device control and auth"""
        
        # Authentication routes
        @self.app.route('/login')
        def login_page():
            """Login page"""
            if 'user' in session:
                return redirect(url_for('index'))
            return render_template('login.html')
        
        @self.app.route('/api/login', methods=['POST'])
        def api_login():
            """Login API endpoint"""
            try:
                data = request.get_json()
                username = data.get('username')
                password = data.get('password')
                
                if not username or not password:
                    return jsonify({'error': 'Username and password required'}), 400
                
                success, message = self.auth_manager.authenticate(username, password)
                
                if success:
                    user_info = self.auth_manager.users[username]
                    session['user'] = {
                        'username': username,
                        'role': user_info['role'],
                        'must_change_password': user_info.get('must_change_password', False)
                    }
                    return jsonify({
                        'success': True,
                        'message': message,
                        'user': session['user']
                    })
                else:
                    return jsonify({'error': message}), 401
                    
            except Exception as e:
                logger.error(f"Login error: {e}")
                return jsonify({'error': 'Login failed'}), 500
        
        @self.app.route('/api/logout', methods=['POST'])
        def api_logout():
            """Logout API endpoint"""
            session.clear()
            return jsonify({'success': True, 'message': 'Logged out successfully'})
        
        @self.app.route('/api/change-password', methods=['POST'])
        @require_auth
        def api_change_password():
            """Change password API endpoint"""
            try:
                data = request.get_json()
                old_password = data.get('old_password')
                new_password = data.get('new_password')
                
                if not old_password or not new_password:
                    return jsonify({'error': 'Old and new passwords required'}), 400
                
                username = session['user']['username']
                success, message = self.auth_manager.change_password(username, old_password, new_password)
                
                if success:
                    session['user']['must_change_password'] = False
                    return jsonify({'success': True, 'message': message})
                else:
                    return jsonify({'error': message}), 400
                    
            except Exception as e:
                logger.error(f"Change password error: {e}")
                return jsonify({'error': 'Failed to change password'}), 500
        
        # Device control routes
        @self.app.route('/api/devices/<mac_address>')
        @require_auth
        def api_device_info(mac_address):
            """Get device information"""
            try:
                device_info = self.device_manager.get_device_info(mac_address)
                return jsonify(device_info)
            except Exception as e:
                logger.error(f"Error getting device info: {e}")
                return jsonify({'error': 'Failed to get device info'}), 500
        
        @self.app.route('/api/devices/<mac_address>/block', methods=['POST'])
        @require_admin
        def api_block_device(mac_address):
            """Block device internet access"""
            try:
                data = request.get_json() or {}
                reason = data.get('reason', 'Manual block via dashboard')
                
                success = self.device_manager.block_device(mac_address, reason)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': f'Device {mac_address} blocked successfully'
                    })
                else:
                    return jsonify({'error': 'Failed to block device'}), 500
                    
            except Exception as e:
                logger.error(f"Error blocking device: {e}")
                return jsonify({'error': 'Failed to block device'}), 500
        
        @self.app.route('/api/devices/<mac_address>/unblock', methods=['POST'])
        @require_admin
        def api_unblock_device(mac_address):
            """Unblock device internet access"""
            try:
                success = self.device_manager.unblock_device(mac_address)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': f'Device {mac_address} unblocked successfully'
                    })
                else:
                    return jsonify({'error': 'Failed to unblock device'}), 500
                    
            except Exception as e:
                logger.error(f"Error unblocking device: {e}")
                return jsonify({'error': 'Failed to unblock device'}), 500
        
        @self.app.route('/api/devices/<mac_address>/schedule', methods=['POST'])
        @require_admin
        def api_set_device_schedule(mac_address):
            """Set device access schedule"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Schedule configuration required'}), 400
                
                success = self.device_manager.set_device_schedule(mac_address, data)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': f'Schedule set for device {mac_address}'
                    })
                else:
                    return jsonify({'error': 'Failed to set schedule'}), 500
                    
            except Exception as e:
                logger.error(f"Error setting device schedule: {e}")
                return jsonify({'error': 'Failed to set schedule'}), 500
        
        @self.app.route('/api/devices/<mac_address>/content-filter', methods=['POST'])
        @require_admin
        def api_set_content_filter(mac_address):
            """Set device content filtering"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Content filter configuration required'}), 400
                
                success = self.device_manager.set_content_filter(mac_address, data)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': f'Content filter set for device {mac_address}'
                    })
                else:
                    return jsonify({'error': 'Failed to set content filter'}), 500
                    
            except Exception as e:
                logger.error(f"Error setting content filter: {e}")
                return jsonify({'error': 'Failed to set content filter'}), 500
        
        # Original dashboard routes
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            if 'user' not in session:
                return redirect(url_for('login_page'))
            return render_template('dashboard.html')
        
        @self.app.route('/device/<mac_address>')
        @require_auth
        def device_control_page(mac_address):
            """Device control page"""
            return render_template('device_control.html', mac_address=mac_address)
        
        @self.app.before_request
        def before_request():
            """Track client connections and check authentication"""
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            self.stats['clients_connected'].add(client_ip)
            
            # Skip auth check for static files and API endpoints that don't require auth
            if request.endpoint in ['static', 'login_page', 'api_login']:
                return
            
            # Check if user is authenticated for protected routes
            if request.endpoint and not request.endpoint.startswith('api_'):
                if 'user' not in session and request.endpoint != 'login_page':
                    return redirect(url_for('login_page'))
        
        @self.app.route('/api/system')
        @require_auth
        def api_system():
            """System information endpoint"""
            self.stats['requests_served'] += 1
            
            try:
                data = self.cache.get('system')
                if data:
                    self.stats['cache_hits'] += 1
                else:
                    # Fallback: get fresh data
                    data = self.get_system_info()
                    if data:
                        self.cache['system'] = data
                
                logger.debug(f"System API called - CPU: {data.get('cpu', {}).get('percent', 0) if data else 'No data'}%")
                
                if not data:
                    return jsonify({'error': 'No system data available'}), 500
                
                return jsonify(data)
                
            except Exception as e:
                logger.error(f"Error in system API: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/api/wifi')
        @require_auth
        def api_wifi():
            """WiFi devices endpoint with control info"""
            self.stats['requests_served'] += 1
            
            try:
                data = self.cache.get('wifi_devices', [])
                logger.debug(f"WiFi API called - {len(data)} devices")
                return jsonify(data)
                
            except Exception as e:
                logger.error(f"Error in WiFi API: {e}")
                return jsonify([])
        @self.app.route('/api/portscans')
        @require_auth
        def api_portscans():
            """Port scan detection endpoint"""
            self.stats['requests_served'] += 1
            return jsonify(self.cache.get('port_scans', []))

        @self.app.route('/api/connections')
        @require_auth
        def api_connections():
            """Network connections endpoint"""
            self.stats['requests_served'] += 1
            data = self.cache.get('connections', [])
            logger.debug(f"Connections API called - {len(data)} connections")
            return jsonify(data)
        
        @self.app.route('/api/interfaces')
        @require_auth
        def api_interfaces():
            """Network interfaces endpoint"""
            self.stats['requests_served'] += 1
            return jsonify(self.cache.get('interfaces', {}))
        
        @self.app.route('/api/suricata')
        @require_auth
        def api_suricata():
            """Suricata alerts endpoint"""
            self.stats['requests_served'] += 1
            return jsonify(self.cache.get('suricata_alerts', []))
        
        @self.app.route('/api/historical')
        @require_auth
        def api_historical():
            """Historical data endpoint"""
            self.stats['requests_served'] += 1
            with self.lock:
                return jsonify({
                    'cpu': list(self.historical_data['cpu']),
                    'memory': list(self.historical_data['memory']),
                    'network_in': list(self.historical_data['network_in']),
                    'network_out': list(self.historical_data['network_out']),
                    'temperature': list(self.historical_data['temperature']),
                    'timestamps': list(self.historical_data['timestamps'])
                })
        
        @self.app.route('/api/stats')
        @require_auth
        def api_stats():
            """Dashboard statistics endpoint"""
            uptime = datetime.now() - self.stats['uptime_start']
            return jsonify({
                'requests_served': self.stats['requests_served'],
                'cache_hits': self.stats['cache_hits'],
                'cache_hit_rate': round((self.stats['cache_hits'] / max(1, self.stats['requests_served'])) * 100, 1),
                'errors': self.stats['errors'],
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_formatted': str(uptime).split('.')[0],
                'clients_connected': len(self.stats['clients_connected']),
                'last_update': self.cache.get('last_update', 'Never'),
                'blocked_devices': len(self.device_manager.blocked_devices),
                'devices_with_schedules': len(self.device_manager.device_schedules),
                'devices_with_filters': len(self.device_manager.content_filters)
            })
        
        @self.app.route('/api/health')
        def api_health():
            """Health check endpoint (no auth required)"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '3.0.0-enhanced',
                'authenticated': 'user' in session,
                'cache_age_seconds': (datetime.now() - datetime.fromisoformat(self.cache.get('last_update', datetime.now().isoformat()))).seconds if self.cache.get('last_update') else 0
            })
        
        @self.app.route('/api/user-info')
        @require_auth
        def api_user_info():
            """Get current user information"""
            return jsonify({
                'user': session.get('user'),
                'session_valid': True
            })
        
        # Admin routes
        @self.app.route('/api/admin/users', methods=['GET'])
        @require_admin
        def api_list_users():
            """List all users (admin only)"""
            try:
                users_info = []
                for username, user_data in self.auth_manager.users.items():
                    users_info.append({
                        'username': username,
                        'role': user_data['role'],
                        'created_at': user_data['created_at'],
                        'last_login': user_data.get('last_login'),
                        'must_change_password': user_data.get('must_change_password', False)
                    })
                
                return jsonify({'users': users_info})
                
            except Exception as e:
                logger.error(f"Error listing users: {e}")
                return jsonify({'error': 'Failed to list users'}), 500
        
        @self.app.route('/api/admin/users', methods=['POST'])
        @require_admin
        def api_create_user():
            """Create new user (admin only)"""
            try:
                data = request.get_json()
                username = data.get('username')
                password = data.get('password')
                role = data.get('role', 'user')
                
                if not username or not password:
                    return jsonify({'error': 'Username and password required'}), 400
                
                if role not in ['admin', 'user']:
                    return jsonify({'error': 'Invalid role'}), 400
                
                success, message = self.auth_manager.create_user(username, password, role)
                
                if success:
                    return jsonify({'success': True, 'message': message})
                else:
                    return jsonify({'error': message}), 400
                    
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return jsonify({'error': 'Failed to create user'}), 500
        
        @self.app.route('/api/admin/devices/summary')
        @require_admin
        def api_devices_summary():
            """Get devices management summary"""
            try:
                return jsonify({
                    'total_blocked': len(self.device_manager.blocked_devices),
                    'total_with_schedules': len(self.device_manager.device_schedules),
                    'total_with_filters': len(self.device_manager.content_filters),
                    'blocked_devices': list(self.device_manager.blocked_devices),
                    'scheduled_devices': list(self.device_manager.device_schedules.keys()),
                    'filtered_devices': list(self.device_manager.content_filters.keys())
                })
                
            except Exception as e:
                logger.error(f"Error getting devices summary: {e}")
                return jsonify({'error': 'Failed to get devices summary'}), 500
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({'error': 'Endpoint not found'}), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def start(self, host='0.0.0.0', port=5000, debug=False):
        """Start the enhanced dashboard server"""
        try:
            logger.info(f"🌟 Enhanced Router Dashboard starting on {host}:{port}")
            logger.info("🔐 Authentication Features:")
            logger.info("   • User login/logout system")
            logger.info("   • Role-based access control")
            logger.info("   • Admin and user roles")
            logger.info("   • Password change functionality")
            
            logger.info("🎯 Device Control Features:")
            logger.info("   • Block/unblock devices by MAC")
            logger.info("   • Set internet access schedules")
            logger.info("   • Content filtering (parental controls)")
            logger.info("   • Individual device management")
            
            logger.info("📊 Available endpoints:")
            logger.info("   • /login            - Login page")
            logger.info("   • /                 - Main dashboard (auth required)")
            logger.info("   • /device/<mac>     - Device control page")
            logger.info("   • /api/login        - Authentication")
            logger.info("   • /api/logout       - Logout")
            logger.info("   • /api/devices/*    - Device management")
            logger.info("   • /api/admin/*      - Admin functions")
            
            # Show default admin credentials
            if 'admin' in self.auth_manager.users:
                admin_user = self.auth_manager.users['admin']
                if admin_user.get('must_change_password', False):
                    logger.warning("⚠️  DEFAULT ADMIN CREDENTIALS:")
                    logger.warning("   Username: admin")
                    logger.warning("   Password: admin123")
                    logger.warning("   CHANGE PASSWORD ON FIRST LOGIN!")
            
            # Run Flask app
            self.app.run(host=host, port=port, debug=debug, threaded=True)
            
        except KeyboardInterrupt:
            logger.info("🛑 Shutdown requested by user")
        except Exception as e:
            logger.error(f"💥 Fatal error: {e}")
        finally:
            self.monitoring_active = False
            logger.info("👋 Enhanced Router Dashboard stopped")

def install_dependencies():
    """Install required dependencies"""
    dependencies = [
        'flask',
        'flask-cors', 
        'psutil'
    ]
    
    for dep in dependencies:
        try:
            __import__(dep.replace('-', '_'))
        except ImportError:
            print(f"Installing {dep}...")
            os.system(f"pip install {dep}")

def main():
    """Main entry point"""
    try:
        print("🚀 Enhanced Router Dashboard - Device Control & Authentication")
        print("=" * 65)
        
        # Install dependencies
        install_dependencies()
        
        # Create dashboard instance
        dashboard = EnhancedRouterDashboard()
        
        # Start monitoring thread
        print("🔄 Starting monitoring thread...")
        monitor_thread = threading.Thread(target=dashboard.monitoring_loop, daemon=True)
        monitor_thread.start()
        time.sleep(2)  # Wait for initial data
        
        # Verify monitoring is working
        if dashboard.cache.get('system'):
            print("✅ Monitoring thread working")
        else:
            print("⚠️  Monitoring thread issue - forcing update...")
            dashboard.update_cache()
        
        print("\n🔐 Security Features:")
        print("   • User authentication system")
        print("   • Role-based access control")
        print("   • Device internet blocking")
        print("   • Content filtering")
        print("   • Access scheduling")
        
        print("\n📱 Access Dashboard:")
        print("   • http://localhost:5000")
        print("   • Default login: admin / admin123")
        
        # Start the server
        dashboard.start(host='0.0.0.0', port=5000)
        
    except Exception as e:
        print(f"💥 Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
