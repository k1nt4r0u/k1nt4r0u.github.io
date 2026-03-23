(() => {
    const MIN_QUERY_LENGTH = 2;
    const SECTION_LABELS = {
        writeups: 'Writeup',
        research: 'Research',
        'malware-analysis': 'Malware Analysis',
    };

    const searchIndexPromise = fetch('/index.json')
        .then((response) => {
            if (!response.ok) {
                throw new Error(`Search index request failed with ${response.status}`);
            }

            return response.json();
        })
        .catch((error) => {
            console.error('Error loading search index:', error);
            return [];
        });

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }

    function getSectionLabel(section) {
        return SECTION_LABELS[section] || section;
    }

    function formatDate(dateString) {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    }

    function matchesQuery(item, normalizedQuery) {
        if (item.title?.toLowerCase().includes(normalizedQuery)) {
            return true;
        }

        if (item.description?.toLowerCase().includes(normalizedQuery)) {
            return true;
        }

        if (item.contest?.toLowerCase().includes(normalizedQuery)) {
            return true;
        }

        if (item.content?.toLowerCase().includes(normalizedQuery)) {
            return true;
        }

        return Array.isArray(item.tags) && item.tags.some((tag) => tag.toLowerCase().includes(normalizedQuery));
    }

    function renderHint(container, message) {
        container.innerHTML = `<p class="search-hint">${message}</p>`;
    }

    function renderResults(container, query, results) {
        if (results.length === 0) {
            container.innerHTML = `<p class="no-results">No results found for "<strong>${escapeHtml(query)}</strong>"</p>`;
            return;
        }

        const resultItems = results.map((result) => {
            const resultTags = Array.isArray(result.tags) ? result.tags : [];

            return `
                <article class="search-result-item">
                    <div class="result-header">
                        <h3><a href="${result.permalink}">${escapeHtml(result.title)}</a></h3>
                        <span class="result-section">${escapeHtml(getSectionLabel(result.section))}</span>
                    </div>
                    ${result.contest ? `<p class="result-contest">Contest: ${escapeHtml(result.contest)}</p>` : ''}
                    <p class="result-description">${escapeHtml(result.description || '')}</p>
                    <div class="result-meta">
                        <span class="result-date">${escapeHtml(formatDate(result.date))}</span>
                        ${resultTags.length > 0 ? `
                            <div class="result-tags">
                                ${resultTags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                </article>
            `;
        }).join('');

        container.innerHTML = `
            <p class="results-count">Found ${results.length} result${results.length > 1 ? 's' : ''} for "<strong>${escapeHtml(query)}</strong>"</p>
            <div class="search-results-list">${resultItems}</div>
        `;
    }

    async function performSearch(query, container) {
        if (!container) {
            return;
        }

        const trimmedQuery = query.trim();
        if (trimmedQuery.length < MIN_QUERY_LENGTH) {
            renderHint(container, `Enter at least ${MIN_QUERY_LENGTH} characters to search.`);
            return;
        }

        renderHint(container, 'Loading search index...');
        const searchIndex = await searchIndexPromise;
        const normalizedQuery = trimmedQuery.toLowerCase();
        const results = searchIndex.filter((item) => matchesQuery(item, normalizedQuery));
        renderResults(container, trimmedQuery, results);
    }

    document.addEventListener('DOMContentLoaded', () => {
        const searchInput = document.getElementById('search-input');
        const searchResults = document.getElementById('search-results');

        if (!searchInput || !searchResults) {
            return;
        }

        const query = new URLSearchParams(window.location.search).get('q');
        if (query) {
            searchInput.value = query;
            performSearch(query, searchResults);
        }

        searchInput.addEventListener('input', () => {
            performSearch(searchInput.value, searchResults);
        });

        searchInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                performSearch(searchInput.value, searchResults);
            }
        });
    });
})();
