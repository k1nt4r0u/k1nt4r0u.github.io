(() => {
    const HIGHLIGHT_SELECTOR = '.highlight';
    const INITIALIZED_FLAG = 'copyButtonReady';

    function createCopyButton() {
        const button = document.createElement('button');
        button.className = 'copy-code-button';
        button.type = 'button';
        button.setAttribute('aria-label', 'Copy code');
        button.innerHTML = `
            <svg class="icon-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <svg class="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display:none;">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        `;
        return button;
    }

    function getCodeText(block) {
        const codeElement = block.querySelector('td:last-child pre code')
            || block.querySelector('td:last-child pre')
            || block.querySelector('pre code')
            || block.querySelector('code');

        return codeElement ? codeElement.innerText : '';
    }

    function setCopiedState(button, copied) {
        const iconCopy = button.querySelector('.icon-copy');
        const iconCheck = button.querySelector('.icon-check');

        if (!iconCopy || !iconCheck) {
            return;
        }

        iconCopy.style.display = copied ? 'none' : 'block';
        iconCheck.style.display = copied ? 'block' : 'none';
        button.classList.toggle('copied', copied);
    }

    function fallbackCopy(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }

    async function copyText(text) {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            return;
        }

        fallbackCopy(text);
    }

    function enhanceBlock(block) {
        if (!(block instanceof HTMLElement) || block.dataset[INITIALIZED_FLAG] === 'true') {
            return;
        }

        const button = createCopyButton();
        block.style.position = 'relative';
        block.appendChild(button);
        block.dataset[INITIALIZED_FLAG] = 'true';

        button.addEventListener('click', async () => {
            const text = getCodeText(block);
            if (!text) {
                return;
            }

            try {
                await copyText(text);
                setCopiedState(button, true);
                window.setTimeout(() => setCopiedState(button, false), 2000);
            } catch {
                setCopiedState(button, false);
            }
        });
    }

    function enhanceCodeBlocks(root) {
        if (root instanceof HTMLElement && root.matches(HIGHLIGHT_SELECTOR)) {
            enhanceBlock(root);
        }

        root.querySelectorAll?.(HIGHLIGHT_SELECTOR).forEach(enhanceBlock);
    }

    function observeNewCodeBlocks() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node instanceof HTMLElement) {
                        enhanceCodeBlocks(node);
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    document.addEventListener('DOMContentLoaded', () => {
        enhanceCodeBlocks(document);
        observeNewCodeBlocks();
    });
})();
