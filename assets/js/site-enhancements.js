(() => {
  const reduceMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  const REVEAL_SELECTORS = [
    '#single_header',
    '.article-link--card',
    '.article-link--simple',
    '.article-link--related',
    '.article-content > .highlight',
    '.article-content > pre',
    '.article-content > blockquote',
    '.article-content > table',
    '.article-content > figure',
    '.article-content > details',
    '.article-content > .gitea-card-wrapper',
    '.article-content > .gitlab-card-wrapper',
    '.article-content > .github-card-wrapper',
    '.article-content > .codeberg-card-wrapper',
    '.article-content > .forgejo-card-wrapper',
    '.article-content > .huggingface-card-wrapper',
    '#comments',
    '.toc'
  ].join(', ')

  let toastElement
  let toastTimer

  function runWhenReady(callback) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', callback, { once: true })
      return
    }
    callback()
  }

  function isEditableTarget(target) {
    if (!(target instanceof HTMLElement)) {
      return false
    }

    if (target.isContentEditable) {
      return true
    }

    return Boolean(
      target.closest(
        'input, textarea, select, [contenteditable="true"], .aa-Form, .aa-Input, .giscus textarea'
      )
    )
  }

  function getToastElement() {
    if (toastElement) {
      return toastElement
    }

    toastElement = document.createElement('div')
    toastElement.className = 'site-toast'
    toastElement.setAttribute('role', 'status')
    toastElement.setAttribute('aria-live', 'polite')
    document.body.appendChild(toastElement)
    return toastElement
  }

  function showToast(message) {
    const toast = getToastElement()

    toast.textContent = message
    toast.classList.add('is-visible')

    window.clearTimeout(toastTimer)
    toastTimer = window.setTimeout(() => {
      toast.classList.remove('is-visible')
    }, 1800)
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.setAttribute('readonly', '')
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    textarea.style.pointerEvents = 'none'

    document.body.appendChild(textarea)
    textarea.select()
    textarea.setSelectionRange(0, textarea.value.length)

    let copied = false
    try {
      copied = document.execCommand('copy')
    } catch (_) {
      copied = false
    }

    textarea.remove()
    return copied
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
        return true
      }
    } catch (_) {
      return fallbackCopy(text)
    }

    return fallbackCopy(text)
  }

  function initHeadingAnchorCopy() {
    const links = document.querySelectorAll('.heading-anchor-link[href^="#"]')
    if (!links.length) {
      return
    }

    links.forEach(link => {
      link.addEventListener('click', async event => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
          return
        }

        event.preventDefault()

        const href = link.getAttribute('href')
        if (!href) {
          return
        }

        const url = new URL(href, window.location.href)
        const copied = await copyText(url.toString())

        window.history.replaceState(null, '', url.hash)
        const target = document.getElementById(url.hash.slice(1))
        target?.scrollIntoView({
          behavior: reduceMotionQuery.matches ? 'auto' : 'smooth',
          block: 'start'
        })

        showToast(copied ? 'Section link copied' : 'Section link ready')
      })
    })
  }

  function initKeyboardShortcuts() {
    document.addEventListener('keydown', event => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) {
        return
      }

      if (isEditableTarget(event.target)) {
        return
      }

      const key = event.key.toLowerCase()

      if (key === 't') {
        const switcher =
          document.getElementById('appearance-switcher') ||
          document.getElementById('appearance-switcher-mobile')

        if (!switcher) {
          return
        }

        event.preventDefault()
        switcher.click()

        window.requestAnimationFrame(() => {
          const mode = document.documentElement.classList.contains('dark') ? 'Dark mode' : 'Light mode'
          showToast(mode)
        })
        return
      }

      if (key === 'g') {
        event.preventDefault()
        window.scrollTo({
          top: 0,
          behavior: reduceMotionQuery.matches ? 'auto' : 'smooth'
        })
        showToast('Back to top')
      }
    })
  }

  function initRevealOnScroll() {
    const targets = [...document.querySelectorAll(REVEAL_SELECTORS)]
      .filter(element => !element.classList.contains('reveal-on-scroll'))

    if (!targets.length) {
      return
    }

    targets.forEach((element, index) => {
      element.classList.add('reveal-on-scroll')
      element.style.setProperty('--reveal-delay', `${Math.min((index % 6) * 35, 175)}ms`)
    })

    if (reduceMotionQuery.matches || !('IntersectionObserver' in window)) {
      targets.forEach(element => element.classList.add('reveal-in'))
      return
    }

    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) {
            return
          }

          entry.target.classList.add('reveal-in')
          observer.unobserve(entry.target)
        })
      },
      {
        threshold: 0.14,
        rootMargin: '0px 0px -8% 0px'
      }
    )

    targets.forEach(element => observer.observe(element))
  }

  runWhenReady(() => {
    initHeadingAnchorCopy()
    initKeyboardShortcuts()
    initRevealOnScroll()
  })
})()
