(() => {
  "use strict";

  const showButton = document.getElementById("search-button");
  const showButtonMobile = document.getElementById("search-button-mobile");
  const hideButton = document.getElementById("close-search-button");
  const wrapper = document.getElementById("search-wrapper");
  const modal = document.getElementById("search-modal");
  const input = document.getElementById("search-query");
  const output = document.getElementById("search-results");

  if (!wrapper || !modal || !input || !output || !hideButton) {
    return;
  }

  const state = {
    visible: false,
    indexed: false,
    loading: null,
    items: [],
    debounce: 0,
  };

  const normalize = (value) => String(value || "").toLowerCase();
  const displayText = (value, fallback = "") => String(value || fallback || "").trim();
  const resultLinks = () => [...output.querySelectorAll("a")];

  const indexURL = () => {
    const configured = new URL(wrapper.dataset.url || "/", window.location.href);
    const basePath = configured.pathname.replace(/\/?$/, "/");
    return `${window.location.origin}${basePath}index.json`;
  };

  const setStatus = (message) => {
    output.replaceChildren();
    if (!message) {
      return;
    }

    const item = document.createElement("li");
    item.className = "px-3 py-2 text-sm text-neutral-500 dark:text-neutral-400";
    item.textContent = message;
    output.append(item);
  };

  const ensureIndex = () => {
    if (state.indexed) {
      return Promise.resolve();
    }

    if (state.loading) {
      return state.loading;
    }

    setStatus("Loading search...");
    state.loading = fetch(indexURL(), { credentials: "same-origin" })
      .then((response) => (response.ok ? response.json() : []))
      .then((items) => {
        state.items = (Array.isArray(items) ? items : []).map((item) => {
          const title = displayText(item.title);
          const section = displayText(item.section);
          const summary = displayText(item.summary);
          const content = displayText(item.content);
          return {
            title,
            section,
            summary,
            content,
            date: displayText(item.date),
            permalink: displayText(item.permalink, "#"),
            externalUrl: displayText(item.externalUrl),
            haystack: normalize(`${title} ${section} ${summary} ${content}`),
            titleKey: normalize(title),
            sectionKey: normalize(section),
          };
        });
        state.indexed = true;
        setStatus("");
      })
      .catch(() => {
        state.items = [];
        state.indexed = true;
        setStatus("Search index unavailable.");
      });

    return state.loading;
  };

  const scoreItem = (item, tokens, query) => {
    if (!tokens.every((token) => item.haystack.includes(token))) {
      return 0;
    }

    let score = 1;
    if (item.titleKey === query) score += 80;
    if (item.titleKey.startsWith(query)) score += 50;
    if (item.titleKey.includes(query)) score += 30;
    if (item.sectionKey.includes(query)) score += 10;
    score += Math.max(0, 20 - item.title.length / 8);
    return score;
  };

  const createMeta = (item) => {
    const meta = document.createElement("div");
    meta.className = "text-sm text-neutral-500 dark:text-neutral-400";
    meta.append(document.createTextNode(item.section || "Page"));
    if (item.date) {
      const dot = document.createElement("span");
      dot.className = "px-2 text-primary-500";
      dot.textContent = ".";
      meta.append(dot, document.createTextNode(item.date));
    }
    return meta;
  };

  const createResult = (item) => {
    const li = document.createElement("li");
    li.className = "mb-2";

    const link = document.createElement("a");
    link.className =
      "flex items-center px-3 py-2 rounded-md appearance-none bg-neutral-100 dark:bg-neutral-700 focus:bg-primary-100 hover:bg-primary-100 dark:hover:bg-primary-900 dark:focus:bg-primary-900 focus:outline-dotted focus:outline-transparent focus:outline-2";
    link.href = item.externalUrl || item.permalink;
    link.tabIndex = 0;
    if (item.externalUrl) {
      link.target = "_blank";
      link.rel = "noopener";
    }

    const body = document.createElement("div");
    body.className = "grow";

    const title = document.createElement("div");
    title.className = "-mb-1 text-lg font-bold";
    title.textContent = item.title || "Untitled";

    const summary = document.createElement("div");
    summary.className = "text-sm italic";
    summary.textContent = item.summary;

    const arrow = document.createElement("div");
    arrow.className = "ml-2 ltr:block rtl:hidden text-neutral-500";
    arrow.textContent = "->";

    body.append(title, createMeta(item), summary);
    link.append(body, arrow);
    li.append(link);
    return li;
  };

  const executeQuery = (term) => {
    const query = normalize(term).trim();
    if (query.length < 2) {
      setStatus("");
      return;
    }

    if (!state.indexed) {
      ensureIndex().then(() => executeQuery(term));
      return;
    }

    const tokens = query.split(/\s+/).filter(Boolean);
    const results = state.items
      .map((item) => ({ item, score: scoreItem(item, tokens, query) }))
      .filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score || a.item.title.localeCompare(b.item.title))
      .slice(0, 12)
      .map((entry) => entry.item);

    output.replaceChildren(...results.map(createResult));
    if (!results.length) {
      setStatus("No results.");
    }
  };

  const requestQuery = () => {
    window.clearTimeout(state.debounce);
    state.debounce = window.setTimeout(() => executeQuery(input.value), 80);
  };

  const displaySearch = () => {
    if (!state.visible) {
      document.body.style.overflow = "hidden";
      wrapper.style.visibility = "visible";
      input.focus();
      state.visible = true;
    }

    ensureIndex().then(requestQuery);
  };

  const hideSearch = () => {
    if (!state.visible) {
      return;
    }

    document.body.style.overflow = "";
    wrapper.style.visibility = "hidden";
    input.value = "";
    output.replaceChildren();
    document.activeElement?.blur();
    state.visible = false;
  };

  showButton?.addEventListener("click", displaySearch);
  showButtonMobile?.addEventListener("click", displaySearch);
  hideButton.addEventListener("click", hideSearch);
  wrapper.addEventListener("click", hideSearch);
  modal.addEventListener("click", (event) => {
    event.stopPropagation();
    event.stopImmediatePropagation();
  });
  input.addEventListener("input", requestQuery);

  document.addEventListener("keydown", (event) => {
    const active = document.activeElement;
    const tag = active?.tagName;
    const isInput = tag === "INPUT" || tag === "TEXTAREA" || active?.isContentEditable;

    if (event.key === "/" && !state.visible && !isInput) {
      event.preventDefault();
      displaySearch();
      return;
    }

    if (event.key === "Escape") {
      hideSearch();
      return;
    }

    if (!state.visible) {
      return;
    }

    const links = resultLinks();
    const current = links.indexOf(active);

    if (event.key === "ArrowDown" && links.length) {
      event.preventDefault();
      (current < 0 ? links[0] : links[Math.min(current + 1, links.length - 1)]).focus();
    } else if (event.key === "ArrowUp" && links.length) {
      event.preventDefault();
      if (current <= 0) {
        input.focus();
      } else {
        links[current - 1].focus();
      }
    } else if (event.key === "Enter" && active !== input && active?.click) {
      active.click();
    }
  });
})();
