# Dependencias y permisos del sistema de respuesta a incidentes

## Dependencias principales

- PHP >= 7.0 con soporte para SQLite3
- Python >= 3.6 (si se migra el bloqueo de IPs al backend Python)
- SQLite3 (base de datos)
- iptables (en los contenedores/servidores donde se requiera bloqueo de red)

## Permisos necesarios

- El usuario que ejecuta PHP debe tener permisos para ejecutar iptables (normalmente requiere privilegios de sudo). Se recomienda configurar sudoers para permitir la ejecución de iptables sin contraseña para el script PHP correspondiente.
- Permisos de escritura en la base de datos SQLite (`/var/www/html/database/alerts.db`).

## Instalación de dependencias en Debian/Ubuntu

```sh
sudo apt-get update
sudo apt-get install php php-sqlite3 sqlite3 iptables
```

Si se usa Python para el backend:
```sh
sudo apt-get install python3 python3-pip
# Instalar paquetes requeridos en requirements.txt
```

## Notas de seguridad
- Limitar el acceso a los scripts PHP y la base de datos sólo a usuarios autorizados.
- Si se permite a PHP ejecutar iptables mediante sudo, restringir el comando en `/etc/sudoers`.

## Logs y errores
- Los scripts PHP escriben mensajes de error en el log del servidor web (error_log). Revisar estos logs para depuración y monitoreo.

---

Para dudas o problemas, revisar los comentarios en cada script o contactar al responsable del sistema.
