// Confirmação de formulários sem JavaScript inline (compatível com a CSP script-src 'self').
document.addEventListener('submit', function (event) {
    var message = event.target.getAttribute('data-confirm');
    if (message && !window.confirm(message)) {
        event.preventDefault();
    }
});
