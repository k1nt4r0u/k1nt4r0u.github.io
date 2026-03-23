document.getElementById("katex-render") &&
  document.getElementById("katex-render").addEventListener("load", () => {
    renderMathInElement(document.getElementById("main-content") || document.body, {
      delimiters: [
        { left: "$$", right: "$$", display: true },
        { left: "\\[", right: "\\]", display: true },
        { left: "\\(", right: "\\)", display: false },
        { left: "$", right: "$", display: false },
      ],
      throwOnError: false,
    });
  });
