document.addEventListener('DOMContentLoaded', function() {
    // File upload preview
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name;
            if (fileName) {
                const fileLabel = document.querySelector('.file-label');
                if (fileLabel) {
                    fileLabel.textContent = fileName;
                }
            }
        });
    }
    
    // Password confirmation validation
    const passwordForm = document.querySelector('form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', function(e) {
            const password = document.querySelector('input[name="encryption_password"]');
            const confirmPassword = document.querySelector('input[name="confirm_password"]');
            
            if (password && confirmPassword && password.value !== confirmPassword.value) {
                e.preventDefault();
                alert('Passwords do not match!');
            }
        });
    }
    
    // Enable tooltips if using Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    if (typeof bootstrap !== 'undefined') {
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Flash message auto-hide
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.opacity = '0';
            setTimeout(function() {
                message.remove();
            }, 500);
        }, 5000);
    });
});
