// SIMPLE TAB NAVIGATION SCRIPT
// This script handles switching between Password Generator and Phishing Detection tabs

document.addEventListener('DOMContentLoaded', function () {
    const tabPassword = document.getElementById('tabPassword');
    const tabPhishing = document.getElementById('tabPhishing');
    const passwordSection = document.getElementById('passwordSection');
    const phishingSection = document.getElementById('phishingSection');

    // Tab switching for Password Generator
    if (tabPassword) {
        tabPassword.addEventListener('click', function () {
            tabPassword.classList.add('active');
            tabPhishing.classList.remove('active');
            passwordSection.classList.remove('hidden');
            phishingSection.classList.add('hidden');
        });
    }

    // Tab switching for Phishing Detection
    if (tabPhishing) {
        tabPhishing.addEventListener('click', function () {
            tabPhishing.classList.add('active');
            tabPassword.classList.remove('active');
            phishingSection.classList.remove('hidden');
            passwordSection.classList.add('hidden');
        });
    }

    console.log('SecureHub tab navigation initialized!');
});
