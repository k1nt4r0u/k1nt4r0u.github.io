(() => {
  const root = document.documentElement;
  let ticking = false;

  function updateScrollProgress() {
    const scrollTop = window.scrollY || root.scrollTop || 0;
    const scrollableHeight = Math.max(root.scrollHeight - window.innerHeight, 0);
    const progress = scrollableHeight > 0 ? (scrollTop / scrollableHeight) * 100 : 0;

    root.style.setProperty("--scroll-progress", `${Math.min(Math.max(progress, 0), 100)}%`);
    root.style.setProperty("--scroll-progress-opacity", scrollableHeight > 0 ? "1" : "0");
    ticking = false;
  }

  function requestScrollProgressUpdate() {
    if (ticking) {
      return;
    }

    ticking = true;
    window.requestAnimationFrame(updateScrollProgress);
  }

  window.addEventListener("scroll", requestScrollProgressUpdate, { passive: true });
  window.addEventListener("resize", requestScrollProgressUpdate);
  window.addEventListener("load", requestScrollProgressUpdate);
  document.addEventListener("DOMContentLoaded", requestScrollProgressUpdate);
})();
