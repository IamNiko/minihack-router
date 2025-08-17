# MiniHack Router Dashboard

## 📌 Descripción
MiniHack Router Dashboard es una aplicación Flask que combina monitoreo de red en tiempo real, control de dispositivos y alertas de seguridad usando Suricata. El sistema está diseñado para correr en Raspberry Pi u otros servidores Linux, ofreciendo un panel de control con estadísticas, gestión de usuarios y reglas de firewall.

---

## 🚀 Instalación

### 1. Clonar el repositorio
```bash
git clone <TU_REPO_URL> minihack-router
cd minihack-router
```

### 2. Crear entorno virtual
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar dependencias
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ⚙️ Configuración

### 1. Variables de entorno
Crear un archivo `.env` en la raíz del proyecto:

```env
FLASK_ENV=production
FLASK_SECRET_KEY=<genera_uno_con: python -c "import secrets;print(secrets.token_hex(32))">
CORS_ORIGINS=https://theminihack.com
SESSION_COOKIE_SECURE=1
SURICATA_EVE_PATH=/var/log/suricata/eve.json
SURICATA_FASTLOG_PATH=/var/log/suricata/fast.log
```

> ⚠️ **Importante:** nunca subas tu `.env` a GitHub. Usa `.env.example` como referencia.

### 2. Archivos locales
Crea los archivos que usará la app para usuarios y dispositivos:

```bash
touch users_config.json devices_config.json
mkdir -p logs
```

---

## ▶️ Ejecución en desarrollo
```bash
source venv/bin/activate
python3 app.py
```
Acceder en: [http://localhost:5000](http://localhost:5000)

---

## 🛠️ Deploy en Raspberry Pi (systemd)

### 1. Copiar proyecto
```bash
sudo mkdir -p /opt/minihack
sudo chown $USER:$USER /opt/minihack
cd /opt/minihack
git clone <TU_REPO_URL> .
```

### 2. Configurar servicio
Archivo: `/etc/systemd/system/minihack.service`

```ini
[Unit]
Description=MiniHack Router API
After=network.target

[Service]
User=pi
Group=pi
WorkingDirectory=/opt/minihack
EnvironmentFile=/opt/minihack/.env
ExecStart=/opt/minihack/venv/bin/python3 /opt/minihack/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 3. Habilitar y arrancar
```bash
sudo systemctl daemon-reload
sudo systemctl enable minihack
sudo systemctl start minihack
sudo systemctl status minihack -n 50
```

---

## 🔒 Seguridad
- Usa `FLASK_SECRET_KEY` fijo en `.env`, no lo generes dinámicamente.
- Restringe el CORS a tu dominio real.
- Usa `ufw` o iptables para limitar accesos.
- Configura HTTPS si usas Nginx como proxy.

---

## ✅ Endpoints principales
- `/api/health` → estado del servicio
- `/api/login` → login de usuarios
- `/api/devices` → listado y gestión de dispositivos
- `/api/firewall/block` → bloqueo por MAC

---

## 📊 Logs
- Logs de Suricata en `/var/log/suricata/`
- Logs de la app en `logs/`
- Logs de systemd con `journalctl -u minihack -f`

---

## 👨‍💻 Créditos
Proyecto desarrollado por Nicolás Gentile (MiniHack).