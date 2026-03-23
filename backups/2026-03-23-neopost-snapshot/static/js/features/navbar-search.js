(() => {
    const PLACEHOLDER_PHRASES = [
        "$ grep -r 'search'",
        "$ find . -name '*'",
        "$ cat /posts/*",
        "$ ls -la /blog",
        "$ awk '/pattern/'",
    ];

    function buildSearchUrl(query) {
        return `/search?q=${encodeURIComponent(query)}`;
    }

    function initTypingEffect(searchBox) {
        let phraseIndex = 0;
        let charIndex = 0;
        let isDeleting = false;

        function typeNextCharacter() {
            const currentPhrase = PLACEHOLDER_PHRASES[phraseIndex];
            const nextIndex = isDeleting ? charIndex - 1 : charIndex + 1;

            searchBox.placeholder = currentPhrase.substring(0, nextIndex);
            charIndex = nextIndex;

            let delay = isDeleting ? 50 : 100;

            if (!isDeleting && charIndex === currentPhrase.length) {
                isDeleting = true;
                delay = 2000;
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                phraseIndex = (phraseIndex + 1) % PLACEHOLDER_PHRASES.length;
                delay = 500;
            }

            window.setTimeout(typeNextCharacter, delay);
        }

        window.setTimeout(typeNextCharacter, 1000);
    }

    document.addEventListener('DOMContentLoaded', () => {
        const searchBox = document.getElementById('search-box');
        if (!searchBox) {
            return;
        }

        searchBox.addEventListener('keypress', (event) => {
            if (event.key !== 'Enter') {
                return;
            }

            const query = searchBox.value.trim();
            if (!query) {
                return;
            }

            window.location.href = buildSearchUrl(query);
        });

        initTypingEffect(searchBox);
    });
})();
