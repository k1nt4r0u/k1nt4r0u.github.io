(() => {
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const cards = document.querySelectorAll(".js-writeups-card");

  if (!cards.length) {
    return;
  }

  const clearTransitionHandler = (panel) => {
    if (panel._writeupsTransitionHandler) {
      panel.removeEventListener("transitionend", panel._writeupsTransitionHandler);
      panel._writeupsTransitionHandler = null;
    }
  };

  const setStaticState = (details, panel) => {
    clearTransitionHandler(panel);
    panel.style.willChange = "";
    if (details.open) {
      panel.style.height = "auto";
      panel.style.opacity = "1";
    } else {
      panel.style.height = "0px";
      panel.style.opacity = "0";
    }
    panel.dataset.animating = "false";
  };

  const animatePanel = (details, panel, expand) => {
    clearTransitionHandler(panel);

    const startHeight = panel.getBoundingClientRect().height;

    if (expand) {
      details.open = true;
    }

    const targetHeight = expand ? panel.scrollHeight : 0;

    if (prefersReducedMotion.matches || Math.abs(startHeight - targetHeight) < 1) {
      if (!expand) {
        details.open = false;
      }
      setStaticState(details, panel);
      return;
    }

    panel.dataset.animating = "true";
    panel.style.willChange = "height, opacity";
    panel.style.height = `${startHeight}px`;
    panel.style.opacity = expand ? (startHeight > 0 ? "1" : "0") : "1";

    panel.getBoundingClientRect();

    requestAnimationFrame(() => {
      panel.style.height = `${targetHeight}px`;
      panel.style.opacity = expand ? "1" : "0";
    });

    const onTransitionEnd = (event) => {
      if (event.target !== panel || event.propertyName !== "height") {
        return;
      }

      if (!expand) {
        details.open = false;
      }

      setStaticState(details, panel);
    };

    panel._writeupsTransitionHandler = onTransitionEnd;
    panel.addEventListener("transitionend", onTransitionEnd);
  };

  cards.forEach((details) => {
    const summary = details.querySelector(".writeups-contest-summary");
    const panel = details.querySelector(".js-writeups-panel");

    if (!summary || !panel) {
      return;
    }

    panel.dataset.enhanced = "true";
    setStaticState(details, panel);

    summary.addEventListener("click", (event) => {
      event.preventDefault();
      animatePanel(details, panel, !details.open);
    });
  });

  window.addEventListener("resize", () => {
    cards.forEach((details) => {
      const panel = details.querySelector(".js-writeups-panel");
      if (!panel || details.open === false) {
        return;
      }

      if (panel.dataset.animating === "true") {
        panel.style.height = `${panel.scrollHeight}px`;
        return;
      }

      panel.style.height = "auto";
    });
  });
})();
