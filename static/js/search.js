// Search functionality
(function() {
    let searchIndex = [];
    let indexLoaded = false;
    
    fetch('/index.json')
        .then(response => response.json())
        .then(data => {
            searchIndex = data;
            indexLoaded = true;
            console.log('Search index loaded:', searchIndex.length, 'items');
        })
        .catch(err => {
            console.error('Error loading search index:', err);
        });
    
    document.addEventListener('DOMContentLoaded', function() {
        const searchInput = document.getElementById('search-input');
        const searchResults = document.getElementById('search-results');
        const urlParams = new URLSearchParams(window.location.search);
        const query = urlParams.get('q');
        
        if (query && searchInput) {
            searchInput.value = query;
            const checkIndex = setInterval(() => {
                if (indexLoaded) {
                    clearInterval(checkIndex);
                    performSearch(query);
                }
            }, 100);
        }
        
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                const query = this.value.trim();
                if (query.length >= 2) {
                    performSearch(query);
                } else {
                    searchResults.innerHTML = '<p class="search-hint">Enter at least 2 characters to search.</p>';
                }
            });
            
            searchInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    const query = this.value.trim();
                    if (query) {
                        performSearch(query);
                    }
                }
            });
        }
    });
    
    function performSearch(query) {
        const searchResults = document.getElementById('search-results');
        
        if (!indexLoaded) {
            searchResults.innerHTML = '<p class="search-hint">Loading search index...</p>';
            return;
        }
        
        const lowerQuery = query.toLowerCase();
        
        const results = searchIndex.filter(item => {
            if (item.title && item.title.toLowerCase().indexOf(lowerQuery) !== -1) return true;
            if (item.description && item.description.toLowerCase().indexOf(lowerQuery) !== -1) return true;
            if (item.contest && item.contest.toLowerCase().indexOf(lowerQuery) !== -1) return true;
            if (item.content && item.content.toLowerCase().indexOf(lowerQuery) !== -1) return true;
            if (item.tags && Array.isArray(item.tags)) {
                for (let tag of item.tags) {
                    if (tag.toLowerCase().indexOf(lowerQuery) !== -1) return true;
                }
            }
            return false;
        });
        
        displayResults(results, query);
    }
    
    function displayResults(results, query) {
        const searchResults = document.getElementById('search-results');
        
        if (results.length === 0) {
            searchResults.innerHTML = `<p class="no-results">No results found for "<strong>${escapeHtml(query)}</strong>"</p>`;
            return;
        }
        
        let html = `<p class="results-count">Found ${results.length} result${results.length > 1 ? 's' : ''} for "<strong>${escapeHtml(query)}</strong>"</p>`;
        html += '<div class="search-results-list">';
        
        results.forEach(result => {
            const sectionLabel = getSectionLabel(result.section);
            const date = new Date(result.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
            
            html += `
                <article class="search-result-item">
                    <div class="result-header">
                        <h3><a href="${result.permalink}">${escapeHtml(result.title)}</a></h3>
                        <span class="result-section">${sectionLabel}</span>
                    </div>
                    ${result.contest ? `<p class="result-contest">�� ${escapeHtml(result.contest)}</p>` : ''}
                    <p class="result-description">${escapeHtml(result.description || '')}</p>
                    <div class="result-meta">
                        <span class="result-date">📅 ${date}</span>
                        ${result.tags && result.tags.length > 0 ? `
                            <div class="result-tags">
                                ${result.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                </article>
            `;
        });
        
        html += '</div>';
        searchResults.innerHTML = html;
    }
    
    function getSectionLabel(section) {
        const labels = {
            'writeups': '📝 Writeup',
            'research': '🔬 Research',
            'malware-analysis': '🦠 Malware Analysis'
        };
        return labels[section] || section;
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
})();
