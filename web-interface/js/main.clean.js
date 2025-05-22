// Función para inicializar los gráficos
function initCharts() {
    console.log('Inicializando gráficos...');
    
    // Verificar si los elementos del gráfico existen
    const alertTypesCtx = document.getElementById('alertTypesChart');
    const severityCtx = document.getElementById('severityChart');
    
    if (!alertTypesCtx || !severityCtx) {
        console.error('No se encontraron los elementos del gráfico');
        return;
    }
    
    // Debug: mostrar datos en consola
    console.log('Datos disponibles en initCharts:');
    console.log('alertTypesData:', window.alertTypesData);
    console.log('severityData:', window.severityData);
    
    // Verificar si hay datos para mostrar
    if (!window.alertTypesData || !window.alertTypesData.labels || window.alertTypesData.labels.length === 0) {
        console.warn('No hay datos de tipos de alertas para mostrar');
        // Mostrar un mensaje en el contenedor del gráfico
        alertTypesCtx.parentNode.innerHTML += '<p class="no-data">No hay datos disponibles para mostrar</p>';
    } else {
        console.log('Creando gráfico de tipos de alertas con datos:', window.alertTypesData);
        // Gráfico de tipos de alertas
        new Chart(alertTypesCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: window.alertTypesData.labels,
                datasets: [{
                    label: 'Número de Alertas',
                    data: window.alertTypesData.data,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    title: { 
                        display: true, 
                        text: 'Distribución por Tipo de Alerta',
                        font: { size: 16 }
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Número de Alertas'
                        }
                    }
                }
            }
        });
    }
    
    // Verificar si hay datos de severidad para mostrar
    if (!window.severityData || !window.severityData.labels || window.severityData.labels.length === 0) {
        console.warn('No hay datos de severidad para mostrar');
        // Mostrar un mensaje en el contenedor del gráfico
        if (severityCtx && severityCtx.parentNode) {
            severityCtx.parentNode.innerHTML += '<p class="no-data">No hay datos de severidad disponibles</p>';
        }
    } else {
        console.log('Creando gráfico de severidad con datos:', window.severityData);
        // Mapa de colores para la severidad
        // 0: Baja (verde), 1: Media (amarillo), 2: Alta (rojo)
        const severityColors = {
            '0': '#43e97b',  // Baja - Verde
            '1': '#ffd600',  // Media - Amarillo
            '2': '#d50000',  // Alta - Rojo
            '3': '#d50000'   // Crítica - Rojo (en caso de que haya nivel 3)
        };
        
        // Gráfico de distribución de severidad
        new Chart(severityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: window.severityData.labels,
                datasets: [{
                    data: window.severityData.data,
                    backgroundColor: window.severityData.labels.map(label => {
                        // Extraer el número de severidad de la etiqueta (ej: 'Severidad 1' -> 1)
                        const severityMatch = label.match(/\d+/);
                        const severity = severityMatch ? severityMatch[0] : '1'; // Por defecto media si no se puede determinar
                        return severityColors[severity] || '#ffd600'; // Amarillo por defecto
                    }),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            color: '#e0e6ed' // Color del texto de la leyenda para mejor contraste
                        }
                    },
                    title: { 
                        display: true, 
                        text: 'Distribución de Severidad', 
                        font: { size: 16 },
                        padding: { bottom: 15 },
                        color: '#e0e6ed' // Color del título para mejor contraste
                    }
                },
                cutout: '70%',
                radius: '90%'
            }
        });
    }
}

// Inicializar los gráficos cuando el DOM esté completamente cargado
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM completamente cargado, inicializando gráficos...');
    // Verificar si Chart.js está cargado
    if (typeof Chart === 'undefined') {
        console.error('Chart.js no se ha cargado correctamente');
        // Mostrar un mensaje de error en la página
        const chartContainers = document.querySelectorAll('.chart-container');
        chartContainers.forEach(container => {
            container.innerHTML = '<p class="error">Error: No se pudo cargar la biblioteca de gráficos. Por favor, recarga la página.</p>';
        });
        return;
    }
    
    // Verificar si los datos están disponibles
    if (!window.alertTypesData || !window.severityData) {
        console.error('No se encontraron los datos para los gráficos');
        return;
    }
    
    // Inicializar los gráficos
    initCharts();
});

// Asegurarse de que los gráficos se redimensionen correctamente
window.addEventListener('resize', function() {
    // Re-inicializar los gráficos cuando se redimensione la ventana
    if (typeof initCharts === 'function') {
        initCharts();
    }
});
