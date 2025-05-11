<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="assets/logo.png">
    <title>Sistema de Respuesta a Incidentes de Seguridad</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Añadir audio para alertas -->
    <audio id="alertSound" preload="auto">
        <source src="sounds/alert.mp3" type="audio/mpeg">
    </audio>
    <!-- Tipografía tecnológica para títulos -->
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <!-- Componente de notificación de alertas en tiempo real -->
        <div id="alertNotifications" class="alert-notifications"></div>
        
        <header>
            <div class="logo-container">
                <a href="index.php" style="display:flex;align-items:center;text-decoration:none;">
                    <img src="assets/logo.png" alt="Logo">
                    <h1 style="font-family: 'Orbitron', sans-serif;">SecNet</h1>
                </a>
            </div>
            <nav>
                <ul>
                    <li><a href="index.php" class="active"><i class="fas fa-tachometer-alt"></i> Panel</a></li>
                    <li><a href="alerts.php"><i class="fas fa-exclamation-triangle"></i> Alertas</a></li>
                </ul>
            </nav>
        </header>
        
        <main>
            <div class="dashboard-header">
                <h2><i class="fas fa-chart-line"></i> Resumen de Seguridad</h2>
                <div class="date-filter">
                    <select id="timeRange" onchange="updateDashboard()">
                        <option value="">Todas las alertas</option>
                        <option value="24">Últimas 24 horas</option>
                        <option value="48">Últimas 48 horas</option>
                        <option value="168">Últimos 7 días</option>
                        <option value="720">Últimos 30 días</option>
                    </select>
                </div>
            </div>
            <section class="dashboard">
                <div class="stats-container">
                    <?php
                    // Connect to SQLite database
                    $db = new SQLite3('/var/www/html/database/alerts.db');
                    
                    // Obtener IPs bloqueadas
                    $blocked_ip_list = [];
                    $blocked_result = $db->query("SELECT DISTINCT ip_address FROM blocked_ips");
                    while ($row = $blocked_result->fetchArray(SQLITE3_ASSOC)) {
                        $blocked_ip_list[] = $row['ip_address'];
                    }
                    $has_blocked = count($blocked_ip_list) > 0;
                    $blocked_ips_placeholder = $has_blocked ? "'" . implode("','", $blocked_ip_list) . "'" : '';

                    // Generar condiciones dinámicamente
                    // DESACTIVAMOS EL FILTRO PARA MOSTRAR TODA LA INFORMACIÓN
                    $where_not_blocked = "1=1";

                    // Obtener el rango de tiempo seleccionado
                    $timeRange = isset($_GET['timeRange']) ? $_GET['timeRange'] : '';
                    $useTimeFilter = ($timeRange !== '' && is_numeric($timeRange));
                    $timeFilter = $useTimeFilter ? "timestamp > datetime('now', '-$timeRange hours')" : '1=1';

                    // Get alert statistics
                    $total_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE $where_not_blocked AND $timeFilter");
                    $high_severity = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE severity >= 2 AND ($where_not_blocked) AND $timeFilter");
                    $blocked_ips = $db->querySingle("SELECT COUNT(DISTINCT ip_address) FROM blocked_ips");
                    $recent_alerts = $db->querySingle("SELECT COUNT(*) FROM alerts WHERE $timeFilter AND ($where_not_blocked)");

                    // Get alert types for chart data
                    $alert_types = [];
                    $query = "SELECT alert_message, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY alert_message ORDER BY count DESC LIMIT 5";
                    $alert_types_result = $db->query($query);
                    while ($row = $alert_types_result->fetchArray(SQLITE3_ASSOC)) {
                        $alert_types[$row['alert_message']] = $row['count'];
                    }

                    // Get alerts by hour for timeline chart
                    $alerts_by_hour = [];
                    $timeline_query = "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as count FROM alerts WHERE $timeFilter AND ($where_not_blocked) GROUP BY hour ORDER BY hour";
                    $timeline_result = $db->query($timeline_query);
                    while ($row = $timeline_result->fetchArray(SQLITE3_ASSOC)) {
                        $alerts_by_hour[$row['hour']] = $row['count'];
                    }

                    // Generar labels por hora para el rango seleccionado
                    $labels = [];
                    if ($useTimeFilter && is_numeric($timeRange) && $timeRange > 0) {
                        $start = new DateTime("-{$timeRange} hours");
                        $end = new DateTime();
                        $interval = new DateInterval('PT1H');
                        $period = new DatePeriod($start, $interval, $end->add($interval));
                        foreach ($period as $dt) {
                            $labels[] = $dt->format('d-m-Y H:00');
                        }
                    } else {
                        // Por defecto, últimos 7 días, por hora
                        $start = new DateTime("-168 hours");
                        $end = new DateTime();
                        $interval = new DateInterval('PT1H');
                        $period = new DatePeriod($start, $interval, $end->add($interval));
                        foreach ($period as $dt) {
                            $labels[] = $dt->format('d-m-Y H:00');
                        }
                    }

                    // Mapear datos de la base de datos a los labels
                    $alerts_by_hour_full = array_fill_keys($labels, 0);
                    foreach ($alerts_by_hour as $hour => $count) {
                        $h = DateTime::createFromFormat('Y-m-d H:i:s', $hour);
                        if ($h) {
                            $key = $h->format('d-m-Y H:00');
                            if (isset($alerts_by_hour_full[$key])) {
                                $alerts_by_hour_full[$key] = $count;
                            }
                        }
                    }

                    // Get severity distribution
                    $severity_dist = [];
                    $severity_query = "SELECT severity, COUNT(*) as count FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY severity ORDER BY severity";
                    $severity_result = $db->query($severity_query);
                    while ($row = $severity_result->fetchArray(SQLITE3_ASSOC)) {
                        $severity_dist[$row['severity']] = $row['count'];
                    }

                    // Get top attackers data
                    $top_attackers = [];
                    $top_attackers_query = "SELECT src_ip, COUNT(*) as count, MAX(severity) as max_severity FROM alerts WHERE $where_not_blocked AND $timeFilter GROUP BY src_ip ORDER BY count DESC LIMIT 10";
                    $top_attackers_result = $db->query($top_attackers_query);
                    while ($row = $top_attackers_result->fetchArray(SQLITE3_ASSOC)) {
                        $top_attackers[$row['src_ip']] = [
                            'count' => $row['count'],
                            'severity' => $row['max_severity']
                        ];
                    }
                    ?>
                    
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-exclamation-circle"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas Totales</div>
                            <div class="stat-value"><?php echo $total_alerts; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon danger"><i class="fas fa-bolt"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alta Severidad</div>
                            <div class="stat-value"><?php echo $high_severity; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-ban"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">IPs Bloqueadas</div>
                            <div class="stat-value"><?php echo $blocked_ips; ?></div>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon"><i class="fas fa-clock"></i></div>
                        <div class="stat-content">
                            <div class="stat-title">Alertas últimas 24h</div>
                            <div class="stat-value"><?php echo $recent_alerts; ?></div>
                        </div>
                    </div>
                </div>
                <div class="charts-container">
                    <div class="chart-card">
                        <h3><i class="fas fa-chart-line"></i> Línea temporal de alertas</h3>
                        <div class="chart-container">
                            <canvas id="alertTimelineChart"></canvas>
                        </div>
                    </div>
                    <div class="chart-card">
                        <h3><i class="fas fa-chart-bar"></i> Distribución de severidad</h3>
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="top-attackers-section">
                    <h3><i class="fas fa-user-secret"></i> Principales atacantes</h3>
                    <table class="top-attackers-table">
                        <thead>
                            <tr>
                                <th>IP origen</th>
                                <th>Alertas</th>
                                <th>Severidad máx.</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($top_attackers as $ip => $info): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($ip); ?></td>
                                    <td><?php echo $info['count']; ?></td>
                                    <td><?php echo $info['severity']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <div class="recent-alerts">
                    <div class="section-header">
                        <h3><i class="fas fa-bell"></i> Alertas recientes</h3>
                        <a href="alerts.php" class="view-all">Ver todas <i class="fas fa-arrow-right"></i></a>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Hora</th>
                                    <th>IP origen</th>
                                    <th>Alerta</th>
                                    <th>Severidad</th>
                                    <th>Acción</th>
                                    <th>Detalles</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                // Get recent alerts
                                $results = $db->query("SELECT * FROM alerts WHERE $where_not_blocked AND $timeFilter ORDER BY timestamp DESC LIMIT 5");
                                
                                while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                    $severity_class = ($row['severity'] >= 2) ? 'high' : 'low';
                                    echo '<tr>';
                                    echo '<td>' . date('d-m-Y H:i', strtotime($row['timestamp'])) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['src_ip']) . '</td>';
                                    echo '<td>' . htmlspecialchars($row['alert_message']) . '</td>';
                                    echo '<td><span class="severity ' . $severity_class . '">' . htmlspecialchars($row['severity']) . '</span></td>';
                                    echo '<td>' . htmlspecialchars($row['action_taken']) . '</td>';
                                    echo '<td><a href="alert-details.php?id=' . urlencode($row['id']) . '" class="btn btn-icon" title="Ver detalles"><i class="fas fa-eye"></i></a></td>';
                                    echo '</tr>';
                                }
                                
                                $db->close();
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
        </main>
        
        <footer>
            <p>&copy; <?php echo date('Y'); ?> Sistema Automatizado de Respuesta a Incidentes</p>
        </footer>
    </div>
    
    <script>
    // Chart data from PHP
    const alertTypesData = <?php echo json_encode(array_values($alert_types)); ?>;
    const alertTypesLabels = <?php echo json_encode(array_keys($alert_types)); ?>;
    
    const timelineLabels = <?php echo json_encode($labels); ?>;
    const timelineData = <?php echo json_encode(array_values($alerts_by_hour_full)); ?>;
    
    const severityLabels = <?php echo json_encode(array_keys($severity_dist)); ?>;
    const severityData = <?php echo json_encode(array_values($severity_dist)); ?>;
    
    <?php
    $last_alert_row = $db = new SQLite3('/var/www/html/database/alerts.db');
    $last_alert_row = $last_alert_row->querySingle("SELECT timestamp FROM alerts ORDER BY timestamp DESC LIMIT 1");
    if ($last_alert_row) {
        echo "let lastAlertTimestamp = '" . $last_alert_row . "';\n";
    } else {
        echo "let lastAlertTimestamp = '2000-01-01 00:00:00';\n";
    }
    ?>
    </script>
    <script src="js/main.js"></script>
</body>
</html>
