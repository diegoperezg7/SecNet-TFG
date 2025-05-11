// === Notificaciones Web obligatorias ===
function requestNotificationPermissionLoop() {
    if (Notification.permission === 'granted') return;
    Notification.requestPermission().then(permission => {
        if (permission !== 'granted') {
            setTimeout(requestNotificationPermissionLoop, 2000);
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    // Solicitar permiso de notificaciones web de forma obligatoria
    requestNotificationPermissionLoop();
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

// Inicializar sistema de alertas en tiempo real (robustecida)
function initRealtimeAlerts() {
    // Iniciar el polling inmediatamente
    checkForNewAlerts();
    // Configurar intervalo de polling (cada 5 segundos)
    if (window.realtimeInterval) clearInterval(window.realtimeInterval);
    window.realtimeInterval = setInterval(checkForNewAlerts, 5000);
}

// Verificar nuevas alertas (robustecida)
function checkForNewAlerts() {
    // Realizar petición AJAX para verificar nuevas alertas
    fetch(`api/check-alerts.php?last_timestamp=${encodeURIComponent(lastAlertTimestamp)}`)
        .then(response => response.json())
        .then(data => {
            if (data.has_new_alerts) {
                // Actualizar el timestamp para la próxima verificación
                lastAlertTimestamp = data.latest_timestamp;
                // Mostrar notificaciones para nuevas alertas
                if (Array.isArray(data.alerts)) {
                    data.alerts.forEach(alert => {
                        showAlertNotification(alert);
                    });
                }
                // Actualizar estadísticas en el dashboard si estamos en la página principal
                if (typeof updateDashboardStats === 'function' && data.stats) {
                    updateDashboardStats(data.stats);
                }
            }
        })
        .catch(error => {
            console.error('Error checking for new alerts:', error);
            // Nunca detener el polling por error
        });
}

// Mostrar notificación web de alerta
function showWebNotification(alert) {
    if (Notification.permission === 'granted') {
        const severityText = alert.severity >= 2 ? 'ALTA' : (alert.severity == 1 ? 'MEDIA' : 'BAJA');
        const notif = new Notification('Nueva alerta de seguridad', {
            body: `[${severityText}] ${alert.alert_message}\nOrigen: ${alert.src_ip}`,
            icon: '/assets/logo.png',
            tag: 'secnet-alert',
        });
        notif.onclick = function() {
            window.focus();
        };
    }
}

// Mostrar notificación de alerta (robustecida)
function showAlertNotification(alert) {
    const notificationsContainer = document.getElementById('alertNotifications');
    if (!notificationsContainer) {
        console.warn('No se encontró el contenedor de notificaciones.');
        return;
    }
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
    // Notificación web obligatoria
    showWebNotification(alert);
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
    // Espera formato ISO o Y-m-d H:i:s
    const date = new Date(timestamp.replace(' ', 'T'));
    if (isNaN(date)) return timestamp;
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const aaaa = date.getFullYear();
    const hh = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    return `${dd}-${mm}-${aaaa} ${hh}:${min}`;
}

// Ver detalles de alerta (redirigir a la página de detalles)
function viewAlertDetails(alertId) {
    window.location.href = `alert-details.php?id=${alertId}`;
}

// Bloquear IP (enviar solicitud al backend)
function blockIP(ip) {
    if (!ip || typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$|^([a-fA-F0-9:]+)$/.test(ip)) {
        alert('IP inválida. No se puede bloquear.');
        return;
    }
    if (confirm(`¿Estás seguro de que deseas bloquear la IP ${ip}?`)) {
        fetch('api/block-ip.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent('Bloqueo manual desde alertas')}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`IP ${ip} bloqueada exitosamente`);
                window.location.reload();
            } else {
                alert(`Error al bloquear IP: ${data.message || 'Desconocido'}`);
                if (data.details) console.error(data.details);
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
                label: 'Alertas por hora',
                data: timelineData,
                fill: true,
                borderColor: '#1976d2',
                backgroundColor: 'rgba(25, 118, 210, 0.15)',
                tension: 0.2,
                pointRadius: 3,
                pointBackgroundColor: '#1976d2',
                pointBorderColor: '#fff',
                pointHoverRadius: 6,
                pointHoverBackgroundColor: '#1565c0',
                pointHoverBorderColor: '#fff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, position: 'top' },
                title: { display: true, text: 'Línea temporal de alertas', font: { size: 16 } },
                tooltip: {
                    enabled: true,
                    callbacks: {
                        label: function(context) {
                            return `Alertas: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'Fecha y hora' },
                    ticks: {
                        maxTicksLimit: 12,
                        autoSkip: true,
                        callback: function(val, idx) {
                            // Solo mostrar la hora si es el mismo día
                            const label = this.getLabelForValue(val);
                            return label.slice(0,5) + ' ' + label.slice(6,11);
                        }
                    }
                },
                y: {
                    title: { display: true, text: 'Cantidad de Alertas' },
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                }
            }
        }
    });

    // SEVERITY DISTRIBUTION
    const ctx2 = document.getElementById('severityChart').getContext('2d');
    // Map severities to colors: 0 (baja)=verde, 1 (media)=amarillo, 2+=rojo
    const severityColorMap = {
        0: '#00c853',   // verde
        1: '#ffd600',   // amarillo
        2: '#d50000'    // rojo
    };
    // Convierte etiquetas a número y asigna color, por defecto rojo
    const severityColors = severityLabels.map(l => {
        const sev = parseInt(l);
        return severityColorMap.hasOwnProperty(sev) ? severityColorMap[sev] : '#d50000';
    });
    // Debug: mostrar por consola datos y colores
    console.log('severityLabels:', severityLabels);
    console.log('severityData:', severityData);
    console.log('severityColors:', severityColors);
    new Chart(ctx2, {
        type: 'doughnut',
        data: {
            labels: severityLabels,
            datasets: [{
                label: 'Severidad',
                data: severityData,
                backgroundColor: severityColors
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
