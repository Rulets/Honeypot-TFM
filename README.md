# Honeynet TFM — Cowrie + OpenCanary

Honeynet de despliegue automatizado para la captura y el análisis de amenazas
automatizadas en Internet. Expone cuatro servicios trampa representativos
(SSH, Telnet, HTTP y FTP) mediante dos honeypots contenerizados y automatiza todo
el ciclo (endurecimiento del anfitrión, cortafuegos, contención de *egress* y
despliegue) con Ansible.

- **Cowrie** — honeypot de media interacción para **SSH (22)** y **Telnet (23)**.
- **OpenCanary** — honeypot de baja interacción para **HTTP (80)** y **FTP (21)**.

> Repositorio del TFM: <https://github.com/Rulets/Honeypot-TFM>

## Estructura del repositorio

```
.
├── ansible/                     # Automatización del despliegue
│   ├── ansible.cfg
│   ├── inventory.ini            # IP y puerto de la VPS
│   ├── site.yml                 # Playbook principal (aplica los 4 roles)
│   ├── group_vars/
│   │   └── all.yml              # Variables centralizadas del despliegue
│   └── roles/
│       ├── common/              # Base del sistema, NTP y endurecimiento SSH
│       ├── docker/              # Instalación del motor Docker + Compose
│       ├── firewall/            # ufw + contención de egress (anti-pivote)
│       └── honeypots/           # Despliegue de los contenedores
├── docker/                      # Definición de los contenedores
│   ├── docker-compose.yml       # Orquestación de Cowrie y OpenCanary
│   ├── cowrie/
│   │   └── etc/                 # Configuración de Cowrie (solo lectura)
│   └── opencanary/
│       ├── Dockerfile           # Imagen propia de OpenCanary
│       ├── entrypoint.sh        # Arranque del servicio
│       └── opencanary.conf      # Servicios emulados (HTTP, FTP)
├── logs/
│   ├── analysis/
│   │   └── analyze.py           # Script de análisis (solo biblioteca estándar)
│   ├── cowrie/                  # Destino de los registros de Cowrie
│   └── opencanary/              # Destino de los registros de OpenCanary
└── README.md
```

## Requisitos

**Nodo de control (tu equipo):**
- Ansible 2.16 o superior.
- Un par de claves SSH (por defecto se usa `~/.ssh/id_ed25519.pub`).

**Nodo destino (VPS):**
- Ubuntu Server 24.04 LTS recién aprovisionado.
- Accesible como `root` por SSH en el puerto 22 (solo en la primera ejecución).

## Despliegue

1. Indica la IP de la VPS en `ansible/inventory.ini`:

   ```ini
   [honeynet]
   vps ansible_host=CAMBIA_POR_LA_IP ansible_user=root ansible_port=64295
   ```

2. **Primera ejecución** (el SSH todavía está en el puerto 22):

   ```bash
   cd ansible
   ansible-playbook site.yml -e ansible_port=22
   ```

   El playbook mueve el SSH administrativo al puerto **64295**, deshabilita el acceso
   por contraseña, instala Docker, configura `ufw` (denegación por defecto, solo
   22/23/80/21 y el 64295 administrativo), instala la contención de *egress* y levanta
   la honeynet.

3. **Ejecuciones posteriores** (ya en el puerto 64295):

   ```bash
   ansible-playbook site.yml
   ```

## Verificación

```bash
ssh -p 64295 root@<IP-VPS>

# Contenedores activos
docker ps

# Puertos de los honeypots a la escucha (22, 23, 80, 21)
ss -tlnp | grep -E ':22|:23|:80|:21'

# Regla de contención de egress presente (subred 172.28.0.0/24)
iptables -S DOCKER-USER | grep 172.28.0.0/24
```

El despliegue es correcto cuando `honeynet-cowrie` y `honeynet-opencanary` figuran como
activos, los puertos 22/23/80/21 están a la escucha y `DOCKER-USER` incluye la regla
`DROP` para `172.28.0.0/24`.

## Análisis de los registros

Recupera los registros de la VPS y ejecuta el análisis (solo requiere Python 3, sin
dependencias externas):

```bash
# Copia de los registros desde la VPS al nodo de análisis
scp -P 64295 -r root@<IP-VPS>:/opt/honeynet/docker/cowrie/log     ./logs/cowrie
scp -P 64295 -r root@<IP-VPS>:/opt/honeynet/docker/opencanary/log ./logs/opencanary

# Ejecución del análisis (métricas y recuentos del Capítulo 6 de la memoria)
python3 logs/analysis/analyze.py
```

El script recorre de forma transparente tanto el fichero activo como sus rotaciones
comprimidas (`.gz`).

## Nota ética y de datos

El despliegue aplica una **contención de *egress*** que impide a los contenedores
iniciar conexiones salientes: aun comprometido, un honeypot no puede emplearse para
atacar a terceros. En cualquier presentación agregada o ilustrativa de resultados, las
direcciones IP se muestran con el último octeto enmascarado.

## Licencia

Trabajo Fin de Máster. Uso académico.
