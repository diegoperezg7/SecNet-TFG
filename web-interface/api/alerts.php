<?php
header('Content-Type: application/json');
require_once '../includes/db.php';

// Función para validar IP
function isValidIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return false;
    }
    
    // Ignorar IPs internas
    $internalRanges = array(
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16'
    );
    
    foreach ($internalRanges as $range) {
        if (ip_in_range($ip, $range)) {
            return false;
        }
    }
    
    return true;
}

// Función para verificar si una IP está en un rango
function ip_in_range($ip, $range) {
    $ip = ip2long($ip);
    $range = explode('/', $range);
    $start = ip2long($range[0]);
    $mask = (isset($range[1]) ? $range[1] : 32);
    $end = $start | ((1 << (32 - $mask)) - 1);
    return ($ip >= $start && $ip <= $end);
}

// Obtener parámetros
$lastTimestamp = isset($_GET['last_timestamp']) ? $_GET['last_timestamp'] : 0;
$limit = 50; // Límite máximo de alertas por petición

try {
    // Consulta para obtener alertas recientes
    $sql = "SELECT * FROM alerts 
            WHERE timestamp > :last_timestamp 
            AND source_ip != '0.0.0.0' 
            AND source_ip != '255.255.255.255'
            ORDER BY timestamp DESC
            LIMIT :limit";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':last_timestamp' => $lastTimestamp,
        ':limit' => $limit
    ]);

    $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Filtrar y procesar alertas
    $filteredAlerts = array_filter($alerts, function($alert) {
        // Validar IP
        if (!isValidIP($alert['source_ip'])) {
            return false;
        }
        
        // Ignorar tráfico HTTP interno
        if (isInternalIP($alert['source_ip']) && $alert['protocol'] === 'HTTP') {
            return false;
        }
        
        // Para otros tipos de tráfico interno, solo mantener los críticos
        if (isInternalIP($alert['source_ip'])) {
            $criticalTypes = ['SYN Flood', 'ICMP Flood', 'UDP Flood'];
            if (!in_array($alert['type'], $criticalTypes)) {
                return false;
            }
            $alert['severity'] = 'LOW';
        }
        
        // Ignorar alertas con poca severidad de IPs conocidas
        $knownIps = [
            '8.8.8.8', // Google DNS
            '8.8.4.4', // Google DNS
            '1.1.1.1', // Cloudflare DNS
            '1.0.0.1'  // Cloudflare DNS
        ];
        
        if (in_array($alert['source_ip'], $knownIps) && 
            $alert['severity'] !== 'HIGH') {
            return false;
        }
        
        return true;
    });

    // Convertir timestamps a formato Unix
    foreach ($filteredAlerts as &$alert) {
        $alert['timestamp'] = strtotime($alert['timestamp']);
    }

    $alerts = $filteredAlerts;

    echo json_encode($alerts);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Error al obtener alertas: ' . $e->getMessage()]);
}
?>
