let speedHistory = {
    labels: [],
    download: [],
    upload: []
};


const ctx = document.getElementById('speedChart').getContext('2d');
const speedChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: speedHistory.labels,
        datasets: [{
            label: 'Download Speed (Mbps)',
            data: speedHistory.download,
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 3,
            fill: false
        }, {
            label: 'Upload Speed (Mbps)',
            data: speedHistory.upload,
            borderColor: 'rgba(153, 102, 255, 1)',
            borderWidth: 3,
            fill: false
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

document.getElementById('speedTestButton').addEventListener('click', runSpeedTest);

function runSpeedTest() {
    fetch('http://127.0.0.1:5000/speedtest')
        .then(response => response.json())
        .then(data => {
            document.getElementById('download-speed').innerText = data.download;
            document.getElementById('latency').innerText = data.latency;
            document.getElementById('upload-speed').innerText = data.upload;

           
            const currentTime = new Date().toLocaleTimeString();
            speedHistory.labels.push(currentTime);
            speedHistory.download.push(data.download);
            speedHistory.upload.push(data.upload);

            
            speedChart.update();
        })
        .catch(error => {
            console.error('Error fetching speed test data:', error);
            alert('Failed to fetch speed test data');
        });
}
