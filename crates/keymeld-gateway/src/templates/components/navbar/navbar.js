// Navbar burger toggle for mobile
(function() {
    function initNavbarBurger() {
        const burgers = document.querySelectorAll('.navbar-burger');
        burgers.forEach(burger => {
            burger.addEventListener('click', () => {
                const targetId = burger.dataset.target;
                const target = document.getElementById(targetId);
                burger.classList.toggle('is-active');
                if (target) {
                    target.classList.toggle('is-active');
                }
            });
        });
    }

    // Initialize on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNavbarBurger);
    } else {
        initNavbarBurger();
    }

    // Re-initialize after HTMX swaps
    document.addEventListener('htmx:afterSwap', initNavbarBurger);
})();
