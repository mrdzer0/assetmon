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

// Timezone Management
function getUserTimezone() {
    return localStorage.getItem('user_timezone') || Intl.DateTimeFormat().resolvedOptions().timeZone;
}

function setUserTimezone(timezone) {
    if (!timezone) {
        timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    }
    localStorage.setItem('user_timezone', timezone);
    showToast(`Timezone set to ${timezone}`, 'success');

    // Refresh page to apply changes if needed, or trigger re-render
    // For now, reload is safest to update all dates
    setTimeout(() => location.reload(), 1000);
}

// Helper to ensure UTC
function ensureUTC(dateString) {
    if (!dateString) return null;
    // If it's a standard ISO string without timezone info (Z or +HH:MM), append Z
    if (typeof dateString === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(dateString)) {
        return dateString + 'Z';
    }
    return dateString;
}

// Format date
function formatDate(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(ensureUTC(dateString));
    const timezone = getUserTimezone();

    try {
        return date.toLocaleString('default', {
            timeZone: timezone,
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            timeZoneName: 'short'
        });
    } catch (e) {
        console.error(`Invalid timezone ${timezone}, falling back to local`);
        return date.toLocaleString();
    }
}

// Format relative time
function formatRelativeTime(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(ensureUTC(dateString));
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

// Hydrate server-side rendered dates
function hydrateDates() {
    const elements = document.querySelectorAll('.local-date');
    console.log(`Hydrating ${elements.length} date elements...`);
    elements.forEach(el => {
        const dateStr = el.getAttribute('data-date');
        if (dateStr) {
            el.textContent = formatDate(dateStr);
        }
    });
}

// Page-specific initialization
document.addEventListener('DOMContentLoaded', () => {
    initTooltips();
    hydrateDates();

    // Update relative timestamps
    setInterval(() => {
        document.querySelectorAll('[data-timestamp]').forEach(el => {
            const timestamp = el.getAttribute('data-timestamp');
            el.textContent = formatRelativeTime(timestamp);
        });
    }, 60000); // Update every minute
});

// Export functions for use in templates
window.hydrateDates = hydrateDates;

// Export functions for use in templates
window.getUserTimezone = getUserTimezone;
window.setUserTimezone = setUserTimezone;
window.showToast = showToast;
window.apiRequest = apiRequest;
window.formatDate = formatDate;
window.formatRelativeTime = formatRelativeTime;
window.confirmAction = confirmAction;
