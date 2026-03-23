function setBackgroundBlur(targetId, scrollDivisor = 300, disableBlur = false, isMenuBlur = false) {
  if (!targetId) {
    console.error("data-blur-id is null");
    return;
  }
  const blurElement = document.getElementById(targetId);
  if (!blurElement) return;
  if (disableBlur) {
    blurElement.setAttribute("aria-hidden", "true");
    if (!isMenuBlur) {
      blurElement.style.display = "none";
      blurElement.style.opacity = "0";
    } else {
      blurElement.style.display = "";
    }
  } else {
    blurElement.style.display = "";
    blurElement.removeAttribute("aria-hidden");
  }
  let ticking = false;
  const updateBlur = () => {
    if (!disableBlur || isMenuBlur) {
      const scroll = window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0;
      blurElement.style.opacity = Math.min(scroll / scrollDivisor, 1);
    }
    ticking = false;
  };
  const requestBlurUpdate = () => {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(updateBlur);
  };
  blurElement.setAttribute("role", "presentation");
  blurElement.setAttribute("tabindex", "-1");
  window.addEventListener("scroll", requestBlurUpdate, { passive: true });
  window.addEventListener("resize", requestBlurUpdate);
  requestBlurUpdate();
}

document.querySelectorAll("script[data-blur-id]").forEach((script) => {
  const targetId = script.getAttribute("data-blur-id");
  const scrollDivisor = Number(script.getAttribute("data-scroll-divisor") || 300);
  const isMenuBlur = targetId === "menu-blur";
  const settings = JSON.parse(localStorage.getItem("a11ySettings") || "{}");
  const disableBlur = settings.disableBlur || false;
  setBackgroundBlur(targetId, scrollDivisor, disableBlur, isMenuBlur);
});
