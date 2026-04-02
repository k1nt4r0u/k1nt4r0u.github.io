(() => {
  const scrollToTop = document.getElementById("scroll-to-top");

  if (!scrollToTop) {
    return;
  }

  const disableForWriteupsMobile =
    document.body.classList.contains("section-writeups") &&
    window.matchMedia("(max-width: 768px)").matches;

  if (disableForWriteupsMobile) {
    scrollToTop.remove();
    return;
  }

  let ticking = false;

  const updateScrollToTop = () => {
    const isVisible = window.scrollY > window.innerHeight * 0.5;
    scrollToTop.classList.toggle("translate-y-0", isVisible);
    scrollToTop.classList.toggle("opacity-100", isVisible);
    scrollToTop.classList.toggle("translate-y-4", !isVisible);
    scrollToTop.classList.toggle("opacity-0", !isVisible);
    ticking = false;
  };

  const requestScrollToTopUpdate = () => {
    if (ticking) {
      return;
    }

    ticking = true;
    window.requestAnimationFrame(updateScrollToTop);
  };

  window.addEventListener("scroll", requestScrollToTopUpdate, { passive: true });
  window.addEventListener("load", requestScrollToTopUpdate);
  requestScrollToTopUpdate();
})();
