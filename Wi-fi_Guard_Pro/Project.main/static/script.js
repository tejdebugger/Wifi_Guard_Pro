// Fetch the networks and filter based on signal strength
function fetchNetworks() {
    fetch('/scan')
        .then(response => response.json())
        .then(data => {
            const wifiList = document.getElementById('wifi-list');
            const selectedFilter = document.getElementById('signal-filter').value;
            
            wifiList.innerHTML = ''; // Clear existing rows
            
            // Filter data based on selected filter
            const filteredData = data.filter(network => {
                if (selectedFilter === "Strong") {
                    return network.signal_strength >= -50;
                } else if (selectedFilter === "Moderate") {
                    return network.signal_strength < -50 && network.signal_strength >= -70;
                } else if (selectedFilter === "Weak") {
                    return network.signal_strength < -70;
                } else {
                    return true; // If 'All' is selected, return all networks
                }
            });
            
            // Render the filtered networks
            filteredData.forEach(network => {
                const priority = getPriority(network.signal_strength);
                const row = document.createElement('tr');
                
                row.addEventListener('click', () => openModal(network));

                row.innerHTML = `
                    <td>${network.ssid}</td>
                    <td>${network.signal_strength}</td>
                    <td>${network.channel}</td>
                    <td class="tooltip">${priority}
                        <span class="tooltiptext">${getPriorityDescription(priority)}</span>
                    </td>
                `;
                wifiList.appendChild(row);
            });
        })
        .catch(error => console.error('Error:', error));
}

// Get priority based on signal strength
function getPriority(signalStrength) {
    if (signalStrength >= -50) {
        return 1; // Highest priority
    } else if (signalStrength >= -70) {
        return 2; // Medium priority
    } else {
        return 3; // Lowest priority
    }
}

function getPriorityDescription(priority) {
    switch (priority) {
        case 1:
            return "Highest priority (Excellent signal)";
        case 2:
            return "Medium priority (Good signal)";
        case 3:
            return "Lowest priority (Weak signal)";
        default:
            return "";
    }
}

// Open modal with detailed information
function openModal(network) {
    const modal = document.getElementById("network-modal");
    
    const macAddress = network.mac_address ? network.mac_address : 'N/A';
    const encryptionType = network.encryption ? network.encryption : 'N/A';

    const details = `
        <strong>SSID:</strong> ${network.ssid}<br>
        <strong>Signal Strength:</strong> ${network.signal_strength} dBm<br>
        <strong>Channel:</strong> ${network.channel}<br>
        <strong>MAC Address:</strong> ${macAddress}<br>
        <strong>Encryption Type:</strong> ${encryptionType}<br>
    `;
    document.getElementById("network-details").innerHTML = details;
    modal.style.display = "block"; 
}

// Close the modal
function closeModal() {
    const modal = document.getElementById("network-modal");
    modal.style.display = "none"; 
}

// Add event listener for the close button
document.querySelector(".close-button").addEventListener("click", closeModal);

// Close modal if user clicks outside of it
window.onclick = function(event) {
    const modal = document.getElementById("network-modal");
    if (event.target === modal) {
        closeModal();
    }
}


// Event listener for the refresh button
document.getElementById('refresh-button').addEventListener('click', fetchNetworks);

// Event listener for the filter dropdown
document.getElementById('signal-filter').addEventListener('change', fetchNetworks);

// Fetch networks on page load
window.onload = fetchNetworks;
