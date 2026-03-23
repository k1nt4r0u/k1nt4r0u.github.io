(() => {
    const IMAGE_SELECTOR = '.post-content img';
    const MIN_ZOOM = 0.5;
    const MAX_ZOOM = 5;

    function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
    }

    function createLightbox() {
        const lightbox = document.createElement('div');
        lightbox.id = 'image-lightbox';
        lightbox.innerHTML = `
            <span class="lightbox-close">&times;</span>
            <div class="lightbox-image-container">
                <img class="lightbox-content" id="lightbox-img">
            </div>
        `;
        document.body.appendChild(lightbox);
        return lightbox;
    }

    document.addEventListener('DOMContentLoaded', () => {
        const postImages = Array.from(document.querySelectorAll(IMAGE_SELECTOR));
        if (postImages.length === 0) {
            return;
        }

        const lightbox = createLightbox();
        const lightboxImage = lightbox.querySelector('#lightbox-img');
        const imageContainer = lightbox.querySelector('.lightbox-image-container');
        const closeButton = lightbox.querySelector('.lightbox-close');

        if (!(lightboxImage instanceof HTMLImageElement) || !imageContainer || !closeButton) {
            return;
        }

        const state = {
            zoom: 1,
            isDragging: false,
            translateX: 0,
            translateY: 0,
            pointerOffsetX: 0,
            pointerOffsetY: 0,
        };

        function applyTransform({ animated = true } = {}) {
            lightboxImage.style.transition = animated
                ? 'transform 0.2s ease-out'
                : 'none';
            lightboxImage.style.transform = `translate(${state.translateX}px, ${state.translateY}px) scale(${state.zoom})`;
            lightboxImage.style.cursor = state.zoom > 1 ? (state.isDragging ? 'grabbing' : 'grab') : 'default';
        }

        function resetTransform() {
            state.zoom = 1;
            state.translateX = 0;
            state.translateY = 0;
            state.isDragging = false;
            applyTransform();
        }

        function openLightbox(src) {
            lightbox.style.display = 'flex';
            lightboxImage.src = src;
            document.body.style.overflow = 'hidden';
            resetTransform();
        }

        function closeLightbox() {
            lightbox.style.display = 'none';
            document.body.style.overflow = 'auto';
            resetTransform();
        }

        function beginDrag(clientX, clientY) {
            if (state.zoom <= 1) {
                return;
            }

            state.isDragging = true;
            state.pointerOffsetX = clientX - state.translateX;
            state.pointerOffsetY = clientY - state.translateY;
            applyTransform({ animated: false });
        }

        function updateDrag(clientX, clientY) {
            if (!state.isDragging) {
                return;
            }

            state.translateX = clientX - state.pointerOffsetX;
            state.translateY = clientY - state.pointerOffsetY;
            applyTransform({ animated: false });
        }

        function endDrag() {
            if (!state.isDragging) {
                return;
            }

            state.isDragging = false;
            applyTransform({ animated: true });
        }

        function updateZoom(delta) {
            state.zoom = clamp(state.zoom + delta, MIN_ZOOM, MAX_ZOOM);
            applyTransform();
        }

        postImages.forEach((image) => {
            image.style.cursor = 'pointer';
            image.addEventListener('click', () => openLightbox(image.src));
        });

        lightboxImage.addEventListener('mousedown', (event) => {
            event.preventDefault();
            beginDrag(event.clientX, event.clientY);
        });

        document.addEventListener('mousemove', (event) => {
            if (!state.isDragging) {
                return;
            }

            event.preventDefault();
            updateDrag(event.clientX, event.clientY);
        });

        document.addEventListener('mouseup', endDrag);

        lightboxImage.addEventListener('touchstart', (event) => {
            const [touch] = event.touches;
            if (!touch) {
                return;
            }

            beginDrag(touch.clientX, touch.clientY);
        }, { passive: true });

        lightboxImage.addEventListener('touchmove', (event) => {
            if (state.zoom <= 1) {
                return;
            }

            const [touch] = event.touches;
            if (!touch) {
                return;
            }

            event.preventDefault();
            updateDrag(touch.clientX, touch.clientY);
        }, { passive: false });

        lightboxImage.addEventListener('touchend', endDrag);

        lightbox.addEventListener('wheel', (event) => {
            if (lightbox.style.display !== 'flex') {
                return;
            }

            event.preventDefault();
            updateZoom(event.deltaY > 0 ? -0.1 : 0.1);
        }, { passive: false });

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
    });
})();
