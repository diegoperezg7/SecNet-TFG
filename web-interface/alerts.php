<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerts - Security Incident Response System</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
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
                    <li><a href="alerts.php" class="active"><i class="fas fa-exclamation-triangle"></i> Alerts</a></li>
                </ul>
            </nav>
        </header>
        <main>
            <section class="alerts-section">
                <h2>Security Alerts</h2>
                <div class="filters">
                    <form method="get" action="alerts.php">
                        <div class="filter-group">
                            <label for="severity">Severity:</label>
                            <select name="severity" id="severity">
                                <option value="">All</option>
                                <option value="1" <?php echo isset($_GET['severity']) && $_GET['severity'] == '1' ? 'selected' : ''; ?>>Low (1)</option>
                                <option value="2" <?php echo isset($_GET['severity']) && $_GET['severity'] == '2' ? 'selected' : ''; ?>>High (2+)</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label for="ip">IP Address:</label>
                            <input type="text" name="ip" id="ip" value="<?php echo isset($_GET['ip']) ? htmlspecialchars($_GET['ip']) : ''; ?>">
                        </div>
                        <div class="filter-group">
                            <label for="timeframe">Timeframe:</label>
                            <select name="timeframe" id="timeframe">
                                <option value="">All Time</option>
                                <option value="24" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '24' ? 'selected' : ''; ?>>Last 24 Hours</option>
                                <option value="48" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '48' ? 'selected' : ''; ?>>Last 48 Hours</option>
                                <option value="168" <?php echo isset($_GET['timeframe']) && $_GET['timeframe'] == '168' ? 'selected' : ''; ?>>Last Week</option>
                            </select>
                        </div>
                        <button type="submit" class="filter-button">Apply Filters</button>
                    </form>
                </div>
                <div class="alerts-table">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Time</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Alert</th>
                                <th>Protocol</th>
                                <th>Severity</th>
                                <th>Action</th>
                                <th>Operations</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            // Connect to SQLite database
                            $db = new SQLite3('/var/www/html/database/alerts.db');
                            // Build query with filters
                            $query = "SELECT * FROM alerts WHERE 1=1";
                            $params = [];
                            if (isset($_GET['severity']) && $_GET['severity'] !== '') {
                                if ($_GET['severity'] == '1') {
                                    $query .= " AND severity = 1";
                                } else {
                                    $query .= " AND severity >= 2";
                                }
                            }
                            if (isset($_GET['ip']) && $_GET['ip'] !== '') {
                                $ip = $_GET['ip'];
                                $query .= " AND (src_ip LIKE :ip OR dest_ip LIKE :ip)";
                                $params[':ip'] = "%$ip%";
                            }
                            if (isset($_GET['timeframe']) && $_GET['timeframe'] !== '') {
                                $hours = intval($_GET['timeframe']);
                                $query .= " AND timestamp > datetime('now', '-$hours hours')";
                            }
                            $query .= " ORDER BY timestamp DESC LIMIT 100";
                            $stmt = $db->prepare($query);
                            foreach ($params as $key => $value) {
                                $stmt->bindValue($key, $value, SQLITE3_TEXT);
                            }
                            $results = $stmt->execute();
                            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                                echo '<tr>';
                                echo '<td>' . $row['id'] . '</td>';
                                echo '<td>' . htmlspecialchars($row['timestamp']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['src_ip']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['dest_ip']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['alert_message']) . '</td>';
                                echo '<td>' . htmlspecialchars($row['protocol']) . '</td>';
                                $severity_class = ($row['severity'] >= 2) ? 'high' : (($row['severity'] == 1) ? 'medium' : 'low');
                                echo '<td class="severity ' . $severity_class . '">' . $row['severity'] . '</td>';
                                echo '<td>' . htmlspecialchars($row['action_taken']) . '</td>';
                                echo '<td>';
                                echo '<button class="action-btn view-btn" onclick="viewAlertDetails(' . $row['id'] . ')"><i class="fas fa-eye"></i></button>';
                                echo '<button class="action-btn block-btn block-button" onclick="blockIP(\'' . htmlspecialchars($row['src_ip']) . '\')"><i class="fas fa-ban"></i></button>';
                                echo '</td>';
                                echo '</tr>';
                            }
                            $db->close();
                            ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
        <footer>
            <p>&copy; <?php echo date('Y'); ?> Automated Incident Response System</p>
        </footer>
    </div>
    <script src="js/main.js"></script>
    <script>
        // Ya implementado en main.js
    </script>
</body>
</html>
