(() => {
    function addCopyButtons() {
        document.querySelectorAll('.highlight').forEach((box) => {
            if (box.querySelector('.copy-code-button')) {
                return;
            }

            const button = document.createElement('button');
            button.className = 'copy-code-button';
            button.type = 'button';
            button.innerHTML = `
                <svg class="icon-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                <svg class="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display:none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
            `;

            box.style.position = 'relative';
            box.appendChild(button);

            button.addEventListener('click', () => {
                const codeElement = box.querySelector('td:last-child pre code')
                    || box.querySelector('td:last-child pre')
                    || box.querySelector('code');

                if (!codeElement) {
                    return;
                }

                navigator.clipboard.writeText(codeElement.innerText).then(() => {
                    const iconCopy = button.querySelector('.icon-copy');
                    const iconCheck = button.querySelector('.icon-check');

                    if (!iconCopy || !iconCheck) {
                        return;
                    }

                    iconCopy.style.display = 'none';
                    iconCheck.style.display = 'block';
                    button.classList.add('copied');

                    setTimeout(() => {
                        iconCopy.style.display = 'block';
                        iconCheck.style.display = 'none';
                        button.classList.remove('copied');
                    }, 2000);
                });
            });
        });
    }

    function initScrollProgressBar() {
        const scrollProgress = document.getElementById('scroll-progress-bar');

        if (!scrollProgress) {
            return;
        }

        const updateProgress = () => {
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrollPercent = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
            scrollProgress.style.width = `${scrollPercent}%`;
        };

        updateProgress();
        window.addEventListener('scroll', updateProgress, { passive: true });
    }

    function initLightbox() {
        const postImages = document.querySelectorAll('.post-content img');

        if (postImages.length === 0) {
            return;
        }

        const lightbox = document.createElement('div');
        lightbox.id = 'image-lightbox';
        lightbox.innerHTML = `
            <span class="lightbox-close">&times;</span>
            <div class="lightbox-image-container">
                <img class="lightbox-content" id="lightbox-img">
            </div>
        `;
        document.body.appendChild(lightbox);

        let currentZoom = 1;
        let isDragging = false;
        let startX = 0;
        let startY = 0;
        let translateX = 0;
        let translateY = 0;
        let touchStartX = 0;
        let touchStartY = 0;

        const lightboxImg = document.getElementById('lightbox-img');
        const imageContainer = lightbox.querySelector('.lightbox-image-container');
        const closeButton = lightbox.querySelector('.lightbox-close');

        if (!lightboxImg || !imageContainer || !closeButton) {
            return;
        }

        const updateZoom = (scale) => {
            currentZoom = Math.max(0.5, Math.min(5, scale));
            lightboxImg.style.transition = 'transform 0.2s ease-out';
            lightboxImg.style.transform = `translate(${translateX}px, ${translateY}px) scale(${currentZoom})`;
            lightboxImg.style.cursor = currentZoom > 1 ? 'grab' : 'default';
        };

        const closeLightbox = () => {
            lightbox.style.display = 'none';
            document.body.style.overflow = 'auto';
            translateX = 0;
            translateY = 0;
            updateZoom(1);
        };

        lightboxImg.addEventListener('mousedown', (event) => {
            if (currentZoom <= 1) {
                return;
            }

            event.preventDefault();
            isDragging = true;
            startX = event.clientX - translateX;
            startY = event.clientY - translateY;
            lightboxImg.style.cursor = 'grabbing';
            lightboxImg.style.transition = 'none';
        });

        document.addEventListener('mousemove', (event) => {
            if (!isDragging) {
                return;
            }

            event.preventDefault();
            translateX = event.clientX - startX;
            translateY = event.clientY - startY;
            lightboxImg.style.transform = `translate(${translateX}px, ${translateY}px) scale(${currentZoom})`;
        });

        document.addEventListener('mouseup', () => {
            if (!isDragging) {
                return;
            }

            isDragging = false;
            lightboxImg.style.cursor = currentZoom > 1 ? 'grab' : 'default';
            lightboxImg.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
        });

        lightboxImg.addEventListener('touchstart', (event) => {
            if (currentZoom <= 1) {
                return;
            }

            touchStartX = event.touches[0].clientX - translateX;
            touchStartY = event.touches[0].clientY - translateY;
            lightboxImg.style.transition = 'none';
        });

        lightboxImg.addEventListener('touchmove', (event) => {
            if (currentZoom <= 1) {
                return;
            }

            event.preventDefault();
            translateX = event.touches[0].clientX - touchStartX;
            translateY = event.touches[0].clientY - touchStartY;
            lightboxImg.style.transform = `translate(${translateX}px, ${translateY}px) scale(${currentZoom})`;
        }, { passive: false });

        lightboxImg.addEventListener('touchend', () => {
            if (currentZoom <= 1) {
                return;
            }

            lightboxImg.style.transition = 'transform 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
        });

        lightbox.addEventListener('wheel', (event) => {
            if (lightbox.style.display !== 'flex') {
                return;
            }

            event.preventDefault();
            const delta = event.deltaY > 0 ? -0.1 : 0.1;
            updateZoom(currentZoom + delta);
        }, { passive: false });

        postImages.forEach((image) => {
            image.style.cursor = 'pointer';
            image.addEventListener('click', () => {
                lightbox.style.display = 'flex';
                lightboxImg.src = image.src;
                currentZoom = 1;
                translateX = 0;
                translateY = 0;
                updateZoom(1);
                document.body.style.overflow = 'hidden';
            });
        });

        closeButton.addEventListener('click', closeLightbox);
        lightbox.addEventListener('click', (event) => {
            if (event.target === lightbox || event.target === imageContainer) {
                closeLightbox();
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && lightbox.style.display === 'flex') {
                closeLightbox();
            }
        });
    }

    function initScrollToTopButton() {
        const scrollToTopBtn = document.getElementById('scrollToTopBtn');

        if (!scrollToTopBtn) {
            return;
        }

        const toggleButton = () => {
            if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {
                scrollToTopBtn.classList.add('show');
            } else {
                scrollToTopBtn.classList.remove('show');
            }
        };

        toggleButton();
        window.addEventListener('scroll', toggleButton, { passive: true });
        scrollToTopBtn.addEventListener('touchstart', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
        scrollToTopBtn.addEventListener('click', (event) => {
            event.preventDefault();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    function initSearchBox() {
        const searchBox = document.getElementById('search-box');

        if (!searchBox) {
            return;
        }

        const phrases = [
            "$ grep -r 'search'",
            "$ find . -name '*'",
            "$ cat /posts/*",
            "$ ls -la /blog",
            "$ awk '/pattern/'",
        ];
        let phraseIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typingSpeed = 100;

        searchBox.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                window.location.href = `/search?q=${encodeURIComponent(searchBox.value)}`;
            }
        });

        const typeEffect = () => {
            const currentPhrase = phrases[phraseIndex];

            if (isDeleting) {
                searchBox.placeholder = currentPhrase.substring(0, charIndex - 1);
                charIndex -= 1;
                typingSpeed = 50;
            } else {
                searchBox.placeholder = currentPhrase.substring(0, charIndex + 1);
                charIndex += 1;
                typingSpeed = 100;
            }

            if (!isDeleting && charIndex === currentPhrase.length) {
                isDeleting = true;
                typingSpeed = 2000;
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                phraseIndex = (phraseIndex + 1) % phrases.length;
                typingSpeed = 500;
            }

            setTimeout(typeEffect, typingSpeed);
        };

        setTimeout(typeEffect, 1000);
    }

    document.addEventListener('DOMContentLoaded', () => {
        addCopyButtons();
        setTimeout(addCopyButtons, 500);
        initScrollProgressBar();
        initLightbox();
        initScrollToTopButton();
        initSearchBox();
    });
})();
