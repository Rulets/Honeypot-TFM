#!/usr/bin/env python3
"""Analisis de los registros de la honeynet (Cowrie + OpenCanary).

Solo emplea la biblioteca estandar de Python. Carga los eventos de Cowrie
(JSON, uno por linea, incluidas las rotaciones .gz) y de OpenCanary (texto
plano) y produce un informe con las metricas usadas en el Capitulo 6.
"""
import os, re, sys, gzip, json, glob
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(HERE)
COWRIE_DIR = os.path.join(BASE, "cowrie")
OC_DIR = os.path.join(BASE, "opencanary")


def _open(path):
    """Abre un fichero de texto, transparente a la compresion gzip."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "rt", encoding="utf-8")


def load_cowrie():
    eventos = []
    for path in glob.glob(os.path.join(COWRIE_DIR, "cowrie.json*")):
        with _open(path) as fh:
            for linea in fh:
                if linea.strip():
                    eventos.append(json.loads(linea))
    eventos.sort(key=lambda e: e["timestamp"])
    return eventos


def load_opencanary():
    lineas = []
    for path in glob.glob(os.path.join(OC_DIR, "opencanary.log*")):
        with _open(path) as fh:
            lineas += [ln.rstrip("\n") for ln in fh if ln.strip()]
    return sorted(lineas)


def top(counter, n, total=None):
    for k, c in counter.most_common(n):
        pct = (" (%5.1f%%)" % (100.0 * c / total)) if total else ""
        print("  %-28s %6d%s" % (str(k), c, pct))


# Palabras clave -> categoria de comportamiento (para el mapeo MITRE ATT&CK).
CMD_CATEGORIES = [
    ("Reconocimiento del sistema", ["uname", "/proc/cpuinfo", "/proc/meminfo",
        "lscpu", "free", "uptime", "whoami", "id", "cat /etc/", "hostname"]),
    ("Descubrimiento de red", ["netstat", "ifconfig", "ip a", "arp", "ss "]),
    ("Descubrimiento de ficheros", ["ls ", "pwd", "find "]),
    ("Descarga de binarios", ["wget", "curl", "tftp", "ftpget"]),
    ("Ejecucion", ["chmod", "./", "sh ", "busybox", "bash", "nohup"]),
    ("Persistencia", ["crontab", "authorized_keys", ".ssh", "rc.local",
        "systemctl"]),
    ("Mineria de criptomonedas", ["xmrig", "minerd", "stratum", "cpuminer"]),
    ("Borrado de evidencias", ["history -c", "rm -rf", "rm -f"]),
]


def categorize(cmd):
    for name, kws in CMD_CATEGORIES:
        if any(kw in cmd for kw in kws):
            return name
    return "Otros"


def analyze_cowrie(eventos):
    print("Eventos Cowrie:", len(eventos))
    print("Tipos de evento:")
    top(Counter(e["eventid"] for e in eventos), 10, len(eventos))

    sesiones = defaultdict(list)
    for e in eventos:
        sesiones[e["session"]].append(e)
    print("Sesiones:", len(sesiones))

    fallidos = [e for e in eventos if e["eventid"] == "cowrie.login.failed"]
    ok = [e for e in eventos if e["eventid"] == "cowrie.login.success"]
    intentos = fallidos + ok
    print("Intentos:", len(intentos), " exitos:", len(ok))
    print("Top usuarios:")
    top(Counter(e["username"] for e in intentos), 15, len(intentos))
    print("Top contrasenas:")
    top(Counter(e["password"] for e in intentos), 15, len(intentos))
    print("Top combinaciones:")
    top(Counter("%s / %s" % (e["username"], e["password"])
                for e in intentos), 15, len(intentos))

    ips = Counter(e["src_ip"] for e in eventos)
    dias = defaultdict(set)
    for e in eventos:
        dias[e["src_ip"]].add(e["timestamp"][:10])
    print("IP unicas:", len(ips), " Top IP:")
    top(ips, 20, len(eventos))
    print("Persistencia (dias activos):")
    top(Counter({ip: len(d) for ip, d in dias.items()}), 15)

    print("Eventos por dia:")
    top(Counter(e["timestamp"][:10] for e in eventos), 40)
    print("Eventos por hora:")
    top(Counter(e["timestamp"][11:13] for e in eventos), 24)

    cmds = [e["input"] for e in eventos
            if e["eventid"] == "cowrie.command.input"]
    print("Comandos:", len(cmds), " unicos:", len(set(cmds)))
    print("Por categoria (MITRE):")
    top(Counter(categorize(c) for c in cmds), 12, len(cmds))
    print("Top comandos:")
    top(Counter(cmds), 25, len(cmds))

    url_re = re.compile(r"https?://[^\s;'|]+")
    urls = Counter()
    for c in cmds:
        if any(k in c for k in ("wget", "curl", "tftp")):
            urls.update(url_re.findall(c))
    print("URLs de descarga:", len(urls))
    top(urls, 15)


def analyze_opencanary(lineas):
    print("Eventos OpenCanary:", len(lineas))
    rx = re.compile(r"^(\S+ \S+) UTC \[(\w+)\] (\S+) (.*)$")
    tipos, ips = Counter(), Counter()
    rutas, metodos, estados = Counter(), Counter(), Counter()
    ftp = Counter()
    for ln in lineas:
        m = rx.match(ln)
        if not m:
            continue
        _, tipo, ip, resto = m.groups()
        tipos[tipo] += 1
        ips[ip] += 1
        if tipo == "HTTP":
            h = re.search(r"(GET|POST|HEAD|OPTIONS) (\S+) HTTP/1.1 - (\d{3})",
                          resto)
            if h:
                metodos[h.group(1)] += 1
                rutas[h.group(2)] += 1
                estados[h.group(3)] += 1
        elif tipo == "FTP":
            f = re.search(r"LOGIN (\S+):(\S+)", resto)
            if f:
                ftp["%s / %s" % (f.group(1), f.group(2))] += 1
    print("Por tipo:")
    top(tipos, 5, len(lineas))
    print("Metodos HTTP:"); top(metodos, 6)
    print("Estados HTTP:"); top(estados, 6)
    print("Top rutas:"); top(rutas, 20)
    print("Credenciales FTP:"); top(ftp, 10)


def main():
    eventos = load_cowrie()
    lineas = load_opencanary()
    analyze_cowrie(eventos)
    analyze_opencanary(lineas)
    print("TOTAL:", len(eventos) + len(lineas))


if __name__ == "__main__":
    main()