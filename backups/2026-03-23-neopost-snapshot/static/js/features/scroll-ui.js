(() => {
    function initScrollProgressBar() {
        const progressBar = document.getElementById('scroll-progress-bar');
        if (!progressBar) {
            return;
        }

        const updateProgress = () => {
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrollPercent = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
            progressBar.style.width = `${scrollPercent}%`;
        };

        updateProgress();
        window.addEventListener('scroll', updateProgress, { passive: true });
    }

    function initScrollToTopButton() {
        const scrollToTopButton = document.getElementById('scrollToTopBtn');
        if (!scrollToTopButton) {
            return;
        }

        const toggleVisibility = () => {
            const isVisible = document.body.scrollTop > 100 || document.documentElement.scrollTop > 100;
            scrollToTopButton.classList.toggle('show', isVisible);
        };

        const scrollToTop = (event) => {
            event?.preventDefault();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        };

        toggleVisibility();
        window.addEventListener('scroll', toggleVisibility, { passive: true });
        scrollToTopButton.addEventListener('click', scrollToTop);
        scrollToTopButton.addEventListener('touchstart', scrollToTop, { passive: true });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initScrollProgressBar();
        initScrollToTopButton();
    });
})();
