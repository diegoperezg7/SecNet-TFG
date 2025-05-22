<?php
// Incluir configuración
require_once __DIR__ . '/config.php';

try {
    $pdo = new PDO(
        'mysql:host=localhost;dbname=incident_response',
        'root',
        '',
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8"
        ]
    );
} catch (PDOException $e) {
    error_log("Error de conexión a la base de datos: " . $e->getMessage());
    die("Error de conexión a la base de datos");
}

// Función para validar IP
function isValidIP($ip) {
    if (empty($ip)) return false;
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

// Función para verificar si una IP es interna
function isInternalIP($ip) {
    // IPs internas RFC1918
    $internalRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16'
    ];
    
    foreach ($internalRanges as $range) {
        if (ip_in_range($ip, $range)) {
            return true;
        }
    }
    return false;
}

// Función auxiliar para verificar si una IP está en un rango
function ip_in_range($ip, $range) {
    if (strpos($range, '/') === false) {
        $range .= '/32';
    }
    
    list($range, $netmask) = explode('/', $range, 2);
    $ip_decimal = ip2long($ip);
    $range_decimal = ip2long($range);
    $wildcard_decimal = pow(2, (32 - $netmask)) - 1;
    $netmask_decimal = ~$wildcard_decimal;
    
    return (($ip_decimal & $netmask_decimal) === ($range_decimal & $netmask_decimal));
}
