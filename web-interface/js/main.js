document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Inicializar sistema de alertas en tiempo real (silenciosamente)
    initRealtimeAlerts();
    
    // Confirm before blocking IP
    const blockButtons = document.querySelectorAll('.block-button');
    blockButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to block this IP address?')) {
                e.preventDefault();
            }
        });
    });
    
    // Add timestamp to show when page was last refreshed
    const footer = document.querySelector('footer');
    if (footer) {
        const timestamp = document.createElement('p');
        timestamp.classList.add('refresh-time');
        timestamp.textContent = 'Last refreshed: ' + new Date().toLocaleTimeString();
        footer.prepend(timestamp);
    }
    
    // Map placeholder button
    const loadMapBtn = document.getElementById('loadMapBtn');
    if (loadMapBtn) {
        loadMapBtn.addEventListener('click', function() {
            const mapPlaceholder = document.getElementById('mapPlaceholder');
            mapPlaceholder.innerHTML = '<p>Loading map data...</p>';
            
            // Simulate loading
            setTimeout(() => {
                mapPlaceholder.innerHTML = '<p>IP geolocation data loaded</p><p>10 unique countries detected</p>';
            }, 1500);
        });
    }
});

// Variables para el sistema de alertas en tiempo real
let realtimeInterval;

// Inicializar sistema de alertas en tiempo real (silenciosamente)
function initRealtimeAlerts() {
    // Iniciar el polling inmediatamente
    checkForNewAlerts();
    
    // Configurar intervalo de polling (cada 5 segundos)
    realtimeInterval = setInterval(checkForNewAlerts, 5000);
}

// Verificar nuevas alertas
function checkForNewAlerts() {
    // Realizar petición AJAX para verificar nuevas alertas
    fetch(`api/check-alerts.php?last_timestamp=${encodeURIComponent(lastAlertTimestamp)}`)
        .then(response => response.json())
        .then(data => {
            if (data.has_new_alerts) {
                // Actualizar el timestamp para la próxima verificación
                lastAlertTimestamp = data.latest_timestamp;
                
                // Mostrar notificaciones para nuevas alertas
                data.alerts.forEach(alert => {
                    showAlertNotification(alert);
                });
                
                // Actualizar estadísticas en el dashboard si estamos en la página principal
                updateDashboardStats(data.stats);
            }
        })
        .catch(error => {
            console.error('Error checking for new alerts:', error);
        });
}

// Mostrar notificación de alerta
function showAlertNotification(alert) {
    const notificationsContainer = document.getElementById('alertNotifications');
    if (!notificationsContainer) return;
    
    // Determinar clase de severidad
    let severityClass = 'normal-severity';
    if (alert.severity >= 2) {
        severityClass = 'high-severity';
    } else if (alert.severity == 1) {
        severityClass = 'medium-severity';
    }
    
    // Crear elemento de notificación
    const notification = document.createElement('div');
    notification.className = `alert-toast ${severityClass}`;
    notification.innerHTML = `
        <div class="alert-toast-icon">
            <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="alert-toast-content">
            <div class="alert-toast-title">
                <span>Nueva Alerta de Seguridad</span>
                <span class="severity ${alert.severity >= 2 ? 'high' : 'low'}">${alert.severity}</span>
            </div>
            <div class="alert-toast-message">${alert.alert_message}</div>
            <div class="alert-toast-time">
                <i class="fas fa-clock"></i> ${formatTimestamp(alert.timestamp)}
            </div>
            <div class="alert-toast-info">
                <i class="fas fa-network-wired"></i> IP: ${alert.src_ip}
            </div>
            <div class="alert-toast-actions">
                <button class="alert-toast-button view" onclick="viewAlertDetails(${alert.id})">Ver detalles</button>
                <button class="alert-toast-button block" onclick="blockIP('${alert.src_ip}')">Bloquear IP</button>
            </div>
        </div>
        <button class="alert-toast-close" onclick="closeNotification(this.parentNode)">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Añadir al contenedor
    notificationsContainer.prepend(notification);
    
    // Reproducir sonido de alerta para alertas de alta severidad
    if (alert.severity >= 2) {
        playAlertSound();
    }
    
    // Auto-eliminar después de 15 segundos
    setTimeout(() => {
        if (notification.parentNode) {
            closeNotification(notification);
        }
    }, 15000);
}

// Reproducir sonido de alerta
function playAlertSound() {
    const sound = document.getElementById('alertSound');
    if (sound) {
        sound.currentTime = 0;
        sound.play().catch(e => {
            console.log('Error playing alert sound:', e);
        });
    }
}

// Cerrar notificación con animación
function closeNotification(notification) {
    notification.classList.add('removing');
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 300);
}

// Formatear timestamp para mostrar
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
}

// Ver detalles de alerta (redirigir a la página de detalles)
function viewAlertDetails(alertId) {
    window.location.href = `alert-details.php?id=${alertId}`;
}

// Bloquear IP (enviar solicitud al backend)
function blockIP(ip) {
    if (confirm(`¿Estás seguro de que deseas bloquear la IP ${ip}?`)) {
        fetch('api/block-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `ip=${encodeURIComponent(ip)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} bloqueada exitosamente`);
            } else {
                alert(`Error al bloquear IP: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error blocking IP:', error);
            alert('Error al bloquear IP. Consulta la consola para más detalles.');
        });
    }
}

// Actualizar estadísticas del dashboard
function updateDashboardStats(stats) {
    // Actualizar contadores de estadísticas si existen en la página
    const elements = {
        'total_alerts': document.querySelector('.stat-card:nth-child(1) .stat-number'),
        'high_severity': document.querySelector('.stat-card:nth-child(2) .stat-number'),
        'blocked_ips': document.querySelector('.stat-card:nth-child(3) .stat-number'),
    };
    
    // Actualizar cada elemento si existe
    for (const [key, element] of Object.entries(elements)) {
        if (element && stats[key] !== undefined) {
            element.textContent = stats[key];
        }
    }
    
    // Actualizar tendencias
    const recentTrend = document.querySelector('.stat-card:nth-child(1) .stat-trend');
    if (recentTrend && stats.recent_alerts !== undefined) {
        recentTrend.innerHTML = `
            <i class="fas fa-${stats.recent_alerts > 0 ? 'arrow-up' : 'arrow-down'}"></i>
            ${stats.recent_alerts} in last 24h
        `;
        recentTrend.className = `stat-trend ${stats.recent_alerts > 0 ? 'up' : 'down'}`;
    }
}

// Initialize all charts
function initCharts() {
    // ALERT TIMELINE (alertas por hora)
    const ctx1 = document.getElementById('alertTimelineChart').getContext('2d');
    new Chart(ctx1, {
        type: 'line',
        data: {
            labels: timelineLabels,
            datasets: [{
                label: 'Alertas',
                data: timelineData,
                fill: false,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75,192,192,0.2)',
                tension: 0.2,
                pointRadius: 3,
                pointBackgroundColor: 'rgb(75, 192, 192)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Alert Timeline', font: { size: 16 } }
            },
            scales: {
                x: { title: { display: true, text: 'Hora' } },
                y: { title: { display: true, text: 'Cantidad de Alertas' }, beginAtZero: true }
            }
        }
    });

    // SEVERITY DISTRIBUTION
    const ctx2 = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: severityLabels,
            datasets: [{
                label: 'Severidad',
                data: severityData,
                backgroundColor: ['#ffd600', '#ff9800', '#d50000']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom' },
                title: { display: true, text: 'Distribución de Severidad', font: { size: 16 } }
            }
        }
    });
}

// Function to update dashboard based on time range
function updateDashboard() {
    const timeRange = document.getElementById('timeRange').value;
    // In a real implementation, this would make an AJAX call to get new data
    // For now, we'll just reload the page with a query parameter
    window.location.href = 'index.php?timeRange=' + timeRange;
}
