#!/bin/sh
set -e

# Directorio de logs (montado como volumen hacia el host)
mkdir -p /var/log/opencanary

# OpenCanary lee la configuración de /etc/opencanaryd/opencanary.conf.
# Arranque en primer plano para que el contenedor lo supervise.
exec opencanaryd --dev
