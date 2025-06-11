// toggleDarkMode

const toggleSwitch = document.getElementById('dark-mode-toggle');
const toggleButton = document.querySelector('.toggle');

toggleButton.addEventListener('click', () => {
    toggleSwitch.checked = !toggleSwitch.checked;
    document.body.classList.toggle('dark-mode');

    document.cookie = `dark_mode=${toggleSwitch.checked}; path=/;`;
});

window.addEventListener('DOMContentLoaded', () => {
    const darkMode = document.cookie.split('; ').find(row => row.startsWith('dark_mode='));
    if (darkMode && darkMode.split('=')[1] === 'true') {
        document.body.classList.add('dark-mode');
        toggleSwitch.checked = true;
    }
});


// Sidebar Active Item Toggle
const menuItems = document.querySelectorAll('.menu-item');
const contentSections = document.querySelectorAll('.content-section');

menuItems.forEach(item => {
    item.addEventListener('click', () => {
        document.querySelector('.menu-item.active').classList.remove('active');
        item.classList.add('active');
        contentSections.forEach(section => section.classList.remove('active'));
        const targetSection = item.getAttribute('data-target');
        document.getElementById(targetSection).classList.add('active');
    });
});

// Toggle Dropdown Menu
function toggleDropdown() {
    var dropdown = document.getElementById("dropdown-content");
    dropdown.classList.toggle("show");
}

window.onclick = function(event) {
    if (!event.target.closest('.profile')) {
        var dropdown = document.getElementById("dropdown-content");
        if (dropdown && dropdown.classList.contains('show')) {
            dropdown.classList.remove('show');
        }
    }
}

function toggleNotificationDropdown() {
    const notificationDropdown = document.getElementById("notification-dropdown");
    
    if (notificationDropdown.classList.contains("show")) {
        notificationDropdown.classList.remove("show");
        setTimeout(() => {
            notificationDropdown.style.display = "none"; 
        }, 300); 
    } else {
        notificationDropdown.style.display = "block"; 
        setTimeout(() => {
            notificationDropdown.classList.add("show"); 
        }, 10); 
    }
}

window.onclick = function(event) {
    if (!event.target.matches('.notification')) {
        const dropdowns = document.getElementsByClassName("notification-dropdown");
        for (let i = 0; i < dropdowns.length; i++) {
            const openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
                setTimeout(() => {
                    openDropdown.style.display = "none"; 
                }, 300); 
            }
        }
    }
}
