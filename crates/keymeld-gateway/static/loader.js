// Loader: Load app bundle after DOM is ready
const script = document.createElement('script');
script.type = 'module';
script.src = '/static/app.min.js';
document.head.appendChild(script);
