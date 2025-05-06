<?php
// alert-details.php
// Muestra los detalles de una alerta específica y el historial de la IP

if (!isset($_GET['id'])) {
    header('Location: index.php');
    exit;
}

$id = intval($_GET['id']);
$db = new SQLite3('/var/www/html/database/alerts.db');

// Obtener detalles de la alerta
$stmt = $db->prepare('SELECT * FROM alerts WHERE id = :id');
$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
$result = $stmt->execute();
$alert = $result->fetchArray(SQLITE3_ASSOC);

if (!$alert) {
    echo '<h2>Alerta no encontrada</h2>';
    exit;
}

$src_ip = $alert['src_ip'];
// Obtener historial de la IP
$history = [];
if ($src_ip) {
    $hist_stmt = $db->prepare('SELECT * FROM alerts WHERE src_ip = :src_ip ORDER BY timestamp DESC LIMIT 20');
    $hist_stmt->bindValue(':src_ip', $src_ip, SQLITE3_TEXT);
    $hist_result = $hist_stmt->execute();
    while ($row = $hist_result->fetchArray(SQLITE3_ASSOC)) {
        $history[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alert Details</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-container">
                <i class="fas fa-shield-alt"></i>
                <h1>SecNet</h1>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                    <li><a href="alerts.php"><i class="fas fa-exclamation-triangle"></i> Alerts</a></li>
                </ul>
            </nav>
        </header>
        <main>
            <h2><i class="fas fa-eye"></i> Detalles de la Alerta</h2>
            <section class="alert-details-box">
                <table class="alert-details-table">
                    <tr><th>ID</th><td><?= htmlspecialchars($alert['id']) ?></td></tr>
                    <tr><th>Fecha/Hora</th><td><?= htmlspecialchars($alert['timestamp']) ?></td></tr>
                    <tr><th>IP Origen</th><td><?= htmlspecialchars($alert['src_ip']) ?></td></tr>
                    <tr><th>IP Destino</th><td><?= htmlspecialchars($alert['dst_ip']) ?></td></tr>
                    <tr><th>Puerto</th><td><?= htmlspecialchars($alert['dst_port']) ?></td></tr>
                    <tr><th>Protocolo</th><td><?= htmlspecialchars($alert['protocol']) ?></td></tr>
                    <tr><th>Mensaje</th><td><?= htmlspecialchars($alert['alert_message']) ?></td></tr>
                    <tr><th>Severidad</th><td><?= htmlspecialchars($alert['severity']) ?></td></tr>
                </table>
            </section>
            <h3><i class="fas fa-history"></i> Historial de la IP</h3>
            <section class="alert-history-box">
                <table class="alert-history-table">
                    <thead>
                        <tr>
                            <th>Fecha/Hora</th>
                            <th>Mensaje</th>
                            <th>Severidad</th>
                            <th>Destino</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($history as $h): ?>
                        <tr>
                            <td><?= htmlspecialchars($h['timestamp']) ?></td>
                            <td><?= htmlspecialchars($h['alert_message']) ?></td>
                            <td><?= htmlspecialchars($h['severity']) ?></td>
                            <td><?= htmlspecialchars($h['dst_ip']) ?>:<?= htmlspecialchars($h['dst_port']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>
            <a href="index.php" class="btn"><i class="fas fa-arrow-left"></i> Volver</a>
        </main>
    </div>
</body>
</html>
