// Asset Monitor - Main JavaScript

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = type === 'success' ? 'fa-check-circle' :
                 type === 'error' ? 'fa-exclamation-circle' :
                 'fa-info-circle';

    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// API Helper
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// Format date
function formatDate(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Format relative time
function formatRelativeTime(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'Just now';
}

// Confirm dialog
function confirmAction(message) {
    return confirm(message);
}

// Initialize tooltips
function initTooltips() {
    // Add tooltip functionality if needed
}

// Page-specific initialization
document.addEventListener('DOMContentLoaded', () => {
    initTooltips();

    // Update relative timestamps
    setInterval(() => {
        document.querySelectorAll('[data-timestamp]').forEach(el => {
            const timestamp = el.getAttribute('data-timestamp');
            el.textContent = formatRelativeTime(timestamp);
        });
    }, 60000); // Update every minute
});

// Export functions for use in templates
window.showToast = showToast;
window.apiRequest = apiRequest;
window.formatDate = formatDate;
window.formatRelativeTime = formatRelativeTime;
window.confirmAction = confirmAction;
