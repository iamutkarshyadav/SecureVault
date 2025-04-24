// JavaScript for the File Encryption System

document.addEventListener('DOMContentLoaded', function() {
    // File upload preview
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'No file chosen';
            const fileSize = this.files[0]?.size || 0;
            const fileSizeInKB = (fileSize / 1024).toFixed(2);
            
            // Display file info if needed
            console.log(`Selected file: ${fileName} (${fileSizeInKB} KB)`);
        });
    }
    
    // Password strength meter could be added here
    const passwordInput = document.querySelector('input[name="encryption_password"]');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            // Simple password strength calculation
            let strength = 0;
            const password = this.value;
            
            if (password.length >= 8) strength += 1;
            if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength += 1;
            if (password.match(/\d/)) strength += 1;
            if (password.match(/[^a-zA-Z\d]/)) strength += 1;
            
            // You could update a UI element here to show password strength
            console.log(`Password strength: ${strength}/4`);
        });
    }
    
    // Enable tooltips if using Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    if (typeof bootstrap !== 'undefined') {
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-warning):not(.alert-info)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    });
});
