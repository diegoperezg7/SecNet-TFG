<?php
header('Content-Type: application/json');

// Conectar a la base de datos
$db = new SQLite3('/var/www/html/database/alerts.db');

// Obtener estadísticas del día
$today = date('Y-m-d');
$query = "SELECT 
    COUNT(*) as totalAlerts,
    SUM(CASE WHEN severity >= 2 THEN 1 ELSE 0 END) as criticalAlerts,
    (SELECT COUNT(*) FROM blocked_ips) as blockedIps,
    (SELECT GROUP_CONCAT(DISTINCT src_ip, ', ') FROM alerts WHERE date(timestamp) = ? ORDER BY COUNT(*) DESC LIMIT 3) as topAttackers
FROM alerts WHERE date(timestamp) = ?";

$stmt = $db->prepare($query);
$result = $stmt->execute([$today, $today]);
$row = $result->fetchArray(SQLITE3_ASSOC);

// Formatear top atacantes
$topAttackers = $row['topAttackers'] ? explode(', ', $row['topAttackers']) : [];

// Crear resumen
$summary = [
    'totalAlerts' => $row['totalAlerts'],
    'criticalAlerts' => $row['criticalAlerts'],
    'blockedIps' => $row['blockedIps'],
    'topAttackers' => $topAttackers
];

// Cerrar conexión
$db->close();

// Devolver resumen
echo json_encode(['summary' => $summary]);
?>
