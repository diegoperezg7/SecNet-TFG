<?php
// Este archivo sirve como endpoint para verificar nuevas alertas
header('Content-Type: application/json');

// Conectar a la base de datos SQLite
$db = new SQLite3('/var/www/html/database/alerts.db');

// Obtener el timestamp de la última alerta que el cliente ya conoce
$lastKnownTimestamp = isset($_GET['last_timestamp']) ? $_GET['last_timestamp'] : '';

// Consultar nuevas alertas desde el último timestamp conocido
$query = "SELECT * FROM alerts WHERE timestamp > :last_timestamp ORDER BY timestamp DESC LIMIT 5";
$stmt = $db->prepare($query);
$stmt->bindValue(':last_timestamp', $lastKnownTimestamp, SQLITE3_TEXT);
$result = $stmt->execute();

// Preparar respuesta
$newAlerts = [];
$latestTimestamp = $lastKnownTimestamp;

while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $newAlerts[] = [
        'id' => $row['id'],
        'timestamp' => $row['timestamp'],
        'src_ip' => $row['src_ip'],
        'alert_message' => $row['alert_message'],
        'severity' => $row['severity'],
        'action_taken' => $row['action_taken']
    ];
    
    // Actualizar el timestamp más reciente
    if ($row['timestamp'] > $latestTimestamp) {
        $latestTimestamp = $row['timestamp'];
    }
}

// Obtener estadísticas actualizadas
$total_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts");
$high_severity = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE severity >= 2");
$blocked_ips = $db->querySingle("SELECT COUNT(*) FROM blocked_ips");
$recent_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours')");

// Cerrar la conexión a la base de datos
$db->close();

// Devolver respuesta JSON
echo json_encode([
    'has_new_alerts' => count($newAlerts) > 0,
    'alerts' => $newAlerts,
    'latest_timestamp' => $latestTimestamp,
    'stats' => [
        'total_alerts' => $total_alerts,
        'high_severity' => $high_severity,
        'blocked_ips' => $blocked_ips,
        'recent_alerts' => $recent_alerts
    ]
]);
?>
