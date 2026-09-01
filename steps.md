# Pasos rápidos de despliegue

Guía resumida. Para el detalle, ver `README.md`.

## 0. Preparación (una vez)

```bash
# Clave SSH para el acceso administrativo (si no existe)
ssh-keygen -t ed25519

# Ansible en el nodo de control
ansible --version   # requiere >= 2.16
```

## 1. Configurar el inventario

Edita `ansible/inventory.ini` y sustituye `CAMBIA_POR_LA_IP` por la IP de la VPS.

## 2. Primer despliegue (SSH aún en el puerto 22)

```bash
cd ansible
ansible-playbook site.yml -e ansible_port=22
```

Esto deja la honeynet operativa y mueve el SSH administrativo al puerto 64295.

## 3. Despliegues posteriores (SSH ya en 64295)

```bash
ansible-playbook site.yml
```

## 4. Comprobar

```bash
ssh -p 64295 root@<IP-VPS>
docker ps
ss -tlnp | grep -E ':22|:23|:80|:21'
iptables -S DOCKER-USER | grep 172.28.0.0/24
```

## 5. Analizar

```bash
scp -P 64295 -r root@<IP-VPS>:/opt/honeynet/docker/cowrie/log     ./logs/cowrie
scp -P 64295 -r root@<IP-VPS>:/opt/honeynet/docker/opencanary/log ./logs/opencanary
python3 logs/analysis/analyze.py
```

## Notas

- **Orden de los roles:** `common` → `docker` → `firewall` → `honeypots`.
- **Puertos expuestos:** 22 (SSH), 23 (Telnet), 80 (HTTP), 21 (FTP) y 64295 (admin).
- **Contención de egress:** los contenedores (subred `172.28.0.0/24`) no pueden iniciar
  conexiones salientes; la regla se reaplica en cada arranque vía `systemd`.
- **OpenCanary** emula únicamente HTTP y FTP; el resto de módulos está deshabilitado.
