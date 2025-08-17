#!/usr/bin/env python3
"""
🔐 Módulo de Seguridad Avanzado
Sistema de autenticación y validación robusto con Argon2
"""

import re
import json
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple
import logging

# Dependencias de seguridad
import argon2
from flask import session, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

# Configurar logger
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Excepción personalizada para errores de seguridad"""
    pass

class InputValidator:
    """Validador centralizado de entradas con regex seguros"""
    
    # Patrones de validación
    MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    TIME_PATTERN = re.compile(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
    
    @classmethod
    def validate_mac_address(cls, mac: str) -> bool:
        """Validar formato MAC address"""
        if not isinstance(mac, str) or not mac:
            return False
        return bool(cls.MAC_PATTERN.match(mac))
    
    @classmethod
    def sanitize_mac_address(cls, mac: str) -> str:
        """Limpiar y normalizar MAC address"""
        if not cls.validate_mac_address(mac):
            raise SecurityError(f"Invalid MAC address format: {mac}")
        return mac.lower().replace('-', ':')
    
    @classmethod
    def validate_ip_address(cls, ip: str) -> bool:
        """Validar formato IP address"""
        if not isinstance(ip, str) or not ip:
            return False
        return bool(cls.IP_PATTERN.match(ip))
    
    @classmethod
    def validate_time_format(cls, time_str: str) -> bool:
        """Validar formato de hora HH:MM"""
        if not isinstance(time_str, str) or not time_str:
            return False
        return bool(cls.TIME_PATTERN.match(time_str))
    
    @classmethod
    def validate_domain(cls, domain: str) -> bool:
        """Validar formato de dominio"""
        if not isinstance(domain, str) or not domain:
            return False
        return bool(cls.DOMAIN_PATTERN.match(domain)) and len(domain) <= 253
    
    @classmethod
    def validate_username(cls, username: str) -> bool:
        """Validar formato de username"""
        if not isinstance(username, str) or not username:
            return False
        return bool(cls.USERNAME_PATTERN.match(username))
    
    @classmethod
    def sanitize_domain_list(cls, domains_text: str) -> List[str]:
        """Limpiar lista de dominios bloqueados"""
        if not isinstance(domains_text, str):
            return []
        
        domains = []
        for line in domains_text.split('\n'):
            domain = line.strip().lower()
            if domain and cls.validate_domain(domain):
                domains.append(domain)
            elif domain:  # Dominio inválido
                logger.warning(f"Invalid domain ignored: {domain}")
        
        return domains
    
    @classmethod
    def sanitize_command_arg(cls, arg: str) -> str:
        """Sanitizar argumentos para comandos de sistema"""
        if not isinstance(arg, str):
            raise SecurityError("Command argument must be string")
        
        # Caracteres peligrosos
        dangerous_chars = ['|', ';', '&', '$', '`', '(', ')', '{', '}', '[', ']', '"', "'", '\\']
        
        for char in dangerous_chars:
            if char in arg:
                raise SecurityError(f"Dangerous character '{char}' not allowed in command argument")
        
        return arg.strip()

class SecurePasswordManager:
    """Gestor seguro de contraseñas con Argon2"""
    
    def __init__(self):
        # Configuración segura de Argon2
        self.ph = argon2.PasswordHasher(
            time_cost=3,        # Iteraciones (3 es seguro y rápido)
            memory_cost=65536,  # Memoria en KB (64MB)
            parallelism=1,      # Hilos paralelos
            hash_len=32,        # Longitud del hash
            salt_len=16         # Longitud del salt
        )
    
    def hash_password(self, password: str) -> str:
        """Hash seguro con Argon2"""
        if not isinstance(password, str) or len(password) < 8:
            raise SecurityError("Password must be at least 8 characters")
        
        return self.ph.hash(password)
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verificar password con Argon2"""
        try:
            self.ph.verify(password_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
        except argon2.exceptions.InvalidHash:
            # Hash inválido o legacy
            return False
    
    def verify_legacy_password(self, password: str, legacy_hash: str) -> bool:
        """Verificar password legacy SHA-256"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest() == legacy_hash
    
    def needs_rehash(self, password_hash: str) -> bool:
        """Verificar si el hash necesita ser actualizado"""
        try:
            return self.ph.check_needs_rehash(password_hash)
        except:
            # Si es un hash legacy o inválido, necesita rehash
            return True

class EnhancedAuthManager:
    """Sistema de autenticación mejorado con Argon2 y migración automática"""
    
    def __init__(self, users_file: str = 'users_config.json'):
        self.users_file = users_file
        self.users = {}
        self.failed_attempts = {}  # IP -> {count, last_attempt}
        self.password_manager = SecurePasswordManager()
        self.max_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        
        self.load_users()
    
    def load_users(self):
        """Cargar usuarios desde archivo"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
                logger.info(f"Loaded {len(self.users)} users from {self.users_file}")
            else:
                self.create_default_admin()
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            self.create_default_admin()
    
    def save_users(self):
        """Guardar usuarios a archivo"""
        try:
            # Crear backup antes de guardar
            if os.path.exists(self.users_file):
                backup_file = f"{self.users_file}.backup"
                os.rename(self.users_file, backup_file)
            
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
            
            logger.info("Users configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving users: {e}")
            raise SecurityError(f"Failed to save users: {e}")
    
    def create_default_admin(self):
        """Crear usuario admin por defecto"""
        # Generar contraseña segura aleatoria
        default_password = secrets.token_urlsafe(16)
        
        self.users = {
            'admin': {
                'password_hash': self.password_manager.hash_password(default_password),
                'hash_algorithm': 'argon2',
                'role': 'admin',
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'must_change_password': True,
                'failed_attempts': 0,
                'locked_until': None
            }
        }
        
        self.save_users()
        
        # Mostrar credenciales por defecto
        logger.warning("="*60)
        logger.warning("🔐 DEFAULT ADMIN CREDENTIALS CREATED")
        logger.warning(f"   Username: admin")
        logger.warning(f"   Password: {default_password}")
        logger.warning("   ⚠️  CHANGE PASSWORD IMMEDIATELY!")
        logger.warning("="*60)
    
    def is_ip_locked(self, ip_address: str) -> bool:
        """Verificar si IP está bloqueada por intentos fallidos"""
        if ip_address not in self.failed_attempts:
            return False
        
        attempts_data = self.failed_attempts[ip_address]
        
        if attempts_data['count'] >= self.max_attempts:
            if datetime.now() - attempts_data['last_attempt'] < self.lockout_duration:
                return True
            else:
                # Limpiar intentos fallidos después del lockout
                del self.failed_attempts[ip_address]
        
        return False
    
    def record_failed_attempt(self, ip_address: str):
        """Registrar intento fallido"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {'count': 0, 'last_attempt': datetime.now()}
        
        self.failed_attempts[ip_address]['count'] += 1
        self.failed_attempts[ip_address]['last_attempt'] = datetime.now()
        
        logger.warning(f"Failed login attempt from {ip_address} (attempt {self.failed_attempts[ip_address]['count']})")
    
    def clear_failed_attempts(self, ip_address: str):
        """Limpiar intentos fallidos después de login exitoso"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def authenticate(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, str, Optional[dict]]:
        """Autenticación con protección contra brute force y migración automática"""
        try:
            # Validar entrada
            if not InputValidator.validate_username(username):
                return False, "Formato de usuario inválido", None
            
            if not isinstance(password, str) or len(password) < 1:
                return False, "Contraseña requerida", None
            
            # Verificar bloqueo por IP
            if ip_address and self.is_ip_locked(ip_address):
                remaining_time = self.lockout_duration - (datetime.now() - self.failed_attempts[ip_address]['last_attempt'])
                return False, f"IP bloqueada. Intente en {remaining_time.seconds // 60} minutos", None
            
            # Verificar usuario existe
            if username not in self.users:
                if ip_address:
                    self.record_failed_attempt(ip_address)
                return False, "Usuario no encontrado", None
            
            user = self.users[username]
            
            # Verificar si usuario está bloqueado
            if user.get('locked_until'):
                locked_until = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < locked_until:
                    return False, "Usuario temporalmente bloqueado", None
                else:
                    # Desbloquear usuario
                    user['locked_until'] = None
                    user['failed_attempts'] = 0
            
            # Verificar contraseña
            password_hash = user['password_hash']
            hash_algorithm = user.get('hash_algorithm', 'sha256')
            
            password_valid = False
            need_migration = False
            
            if hash_algorithm == 'argon2':
                password_valid = self.password_manager.verify_password(password, password_hash)
                # Verificar si necesita rehash (parámetros actualizados)
                if password_valid and self.password_manager.needs_rehash(password_hash):
                    need_migration = True
            else:
                # Password legacy (SHA-256)
                password_valid = self.password_manager.verify_legacy_password(password, password_hash)
                need_migration = password_valid  # Migrar si es válido
            
            if not password_valid:
                # Registrar intento fallido
                user['failed_attempts'] = user.get('failed_attempts', 0) + 1
                
                if ip_address:
                    self.record_failed_attempt(ip_address)
                
                # Bloquear usuario después de muchos intentos
                if user['failed_attempts'] >= self.max_attempts:
                    user['locked_until'] = (datetime.now() + self.lockout_duration).isoformat()
                    logger.warning(f"User {username} locked due to too many failed attempts")
                
                self.save_users()
                return False, "Contraseña incorrecta", None
            
            # Login exitoso - limpiar intentos fallidos
            user['failed_attempts'] = 0
            user['locked_until'] = None
            user['last_login'] = datetime.now().isoformat()
            
            if ip_address:
                self.clear_failed_attempts(ip_address)
            
            # Migración automática de password
            if need_migration:
                try:
                    new_hash = self.password_manager.hash_password(password)
                    user['password_hash'] = new_hash
                    user['hash_algorithm'] = 'argon2'
                    logger.info(f"Migrated password for user {username} to Argon2")
                except Exception as e:
                    logger.error(f"Failed to migrate password for {username}: {e}")
            
            self.save_users()
            
            # Preparar datos de usuario para sesión
            user_data = {
                'username': username,
                'role': user['role'],
                'must_change_password': user.get('must_change_password', False),
                'last_login': user['last_login']
            }
            
            logger.info(f"Successful authentication for user {username}")
            return True, "Login exitoso", user_data
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, "Error interno de autenticación", None
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Cambiar contraseña con validaciones"""
        try:
            # Validar entrada
            if not InputValidator.validate_username(username):
                return False, "Usuario inválido"
            
            if len(new_password) < 8:
                return False, "La nueva contraseña debe tener al menos 8 caracteres"
            
            if username not in self.users:
                return False, "Usuario no encontrado"
            
            # Verificar contraseña actual
            success, message, _ = self.authenticate(username, old_password)
            if not success:
                return False, "Contraseña actual incorrecta"
            
            # Actualizar contraseña
            user = self.users[username]
            user['password_hash'] = self.password_manager.hash_password(new_password)
            user['hash_algorithm'] = 'argon2'
            user['must_change_password'] = False
            user['password_changed_at'] = datetime.now().isoformat()
            
            self.save_users()
            
            logger.info(f"Password changed successfully for user {username}")
            return True, "Contraseña cambiada exitosamente"
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False, "Error cambiando contraseña"
    
    def create_user(self, username: str, password: str, role: str = 'user') -> Tuple[bool, str]:
        """Crear nuevo usuario"""
        try:
            # Validar entrada
            if not InputValidator.validate_username(username):
                return False, "Formato de usuario inválido (3-20 caracteres, solo letras, números, _ y -)"
            
            if len(password) < 8:
                return False, "La contraseña debe tener al menos 8 caracteres"
            
            if role not in ['admin', 'user']:
                return False, "Rol inválido"
            
            if username in self.users:
                return False, "Usuario ya existe"
            
            # Crear usuario
            self.users[username] = {
                'password_hash': self.password_manager.hash_password(password),
                'hash_algorithm': 'argon2',
                'role': role,
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'must_change_password': False,
                'failed_attempts': 0,
                'locked_until': None
            }
            
            self.save_users()
            
            logger.info(f"User created: {username} ({role})")
            return True, "Usuario creado exitosamente"
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False, "Error creando usuario"

def setup_security_middleware(app):
    """Configurar middleware de seguridad para Flask"""
    
    # 1. CSRF Protection
    csrf = CSRFProtect(app)
    
    # 2. Rate Limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    
    # 3. Security Headers con Talisman
    Talisman(app, 
        force_https=app.config.get('FORCE_HTTPS', False),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        content_security_policy={
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Para Plotly y código inline
                "https://cdnjs.cloudflare.com"
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",
                "https://cdnjs.cloudflare.com"
            ],
            'font-src': [
                "'self'",
                "https://cdnjs.cloudflare.com"
            ],
            'img-src': [
                "'self'",
                "data:",
                "https:"
            ]
        },
        content_security_policy_nonce_in=['script-src', 'style-src']
    )
    
    logger.info("🛡️ Security middleware configured successfully")
    return csrf, limiter

# Decoradores de seguridad
def require_auth(f):
    """Decorator para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator para requerir rol de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if session.get('user', {}).get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_login(limiter):
    """Rate limiting específico para login"""
    return limiter.limit("5 per minute")

# Utilidades de seguridad
def generate_secure_token(length: int = 32) -> str:
    """Generar token seguro aleatorio"""
    return secrets.token_urlsafe(length)

def get_client_ip() -> str:
    """Obtener IP real del cliente considerando proxies"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

if __name__ == "__main__":
    # Tests básicos
    print("🔐 Testing Security Module")
    
    # Test InputValidator
    validator = InputValidator()
    print(f"MAC validation: {validator.validate_mac_address('aa:bb:cc:dd:ee:ff')}")
    print(f"IP validation: {validator.validate_ip_address('192.168.1.1')}")
    
    # Test PasswordManager
    pm = SecurePasswordManager()
    test_password = "test123456"
    hash_result = pm.hash_password(test_password)
    print(f"Password hash: {hash_result[:50]}...")
    print(f"Password verify: {pm.verify_password(test_password, hash_result)}")
    
    print("✅ Security module tests completed")
