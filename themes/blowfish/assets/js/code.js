var scriptBundle = document.getElementById("script-bundle");
var copyText = scriptBundle?.getAttribute("data-copy") || "Copy";
var copiedText = scriptBundle?.getAttribute("data-copied") || "Copied";
var copyIcon =
  '<svg class="copy-button__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M9 9h10v10H9z"/><path d="M5 5h10v4"/><path d="M5 5v10h4"/></svg>';
var copiedIcon =
  '<svg class="copy-button__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="m5 12.5 4.2 4.2L19 7"/></svg>';

function setCopyButtonState(button, state) {
  const isCopied = state === "copied";
  button.innerHTML = isCopied ? copiedIcon : copyIcon;
  button.ariaLabel = isCopied ? copiedText : copyText;
  button.title = isCopied ? copiedText : copyText;
  button.classList.toggle("is-copied", isCopied);
}

function createCopyButton(highlightWrapper) {
  const highlightDiv = highlightWrapper.querySelector(".highlight") || highlightWrapper;
  if (highlightDiv.querySelector(":scope > .copy-button")) return;

  const button = document.createElement("button");
  button.className = "copy-button";
  button.type = "button";
  setCopyButtonState(button, "copy");
  button.addEventListener("click", () => copyCodeToClipboard(button, highlightWrapper));
  highlightDiv.insertBefore(button, highlightDiv.firstChild);
}

async function copyCodeToClipboard(button, highlightWrapper) {
  const codeToCopy = getCodeText(highlightWrapper);

  function fallback(codeToCopy, highlightWrapper) {
    const textArea = document.createElement("textArea");
    textArea.contentEditable = "true";
    textArea.readOnly = "false";
    textArea.className = "copy-textarea";
    textArea.value = codeToCopy;
    highlightWrapper.insertBefore(textArea, highlightWrapper.firstChild);
    const range = document.createRange();
    range.selectNodeContents(textArea);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    textArea.focus();
    textArea.setSelectionRange(0, 999999);
    document.execCommand("copy");
    highlightWrapper.removeChild(textArea);
  }

  try {
    const result = await navigator.permissions.query({ name: "clipboard-write" });
    if (result.state == "granted" || result.state == "prompt") {
      await navigator.clipboard.writeText(codeToCopy);
    } else {
      fallback(codeToCopy, highlightWrapper);
    }
  } catch (_) {
    fallback(codeToCopy, highlightWrapper);
  } finally {
    button.blur();
    setCopyButtonState(button, "copied");
    setTimeout(function () {
      setCopyButtonState(button, "copy");
    }, 2000);
  }
}

function getCodeText(highlightWrapper) {
  const highlightDiv = highlightWrapper.querySelector(".highlight");
  if (!highlightDiv) return "";

  const codeBlock = highlightDiv.querySelector("code");
  const inlineLines = codeBlock?.querySelectorAll(".cl"); // linenos=inline
  const tableCodeCell = highlightDiv?.querySelector(".lntable .lntd:last-child code"); // linenos=table

  if (!codeBlock) return "";

  if (inlineLines.length > 0) {
    const cleanedLines = Array.from(inlineLines).map((line) => line.textContent.replace(/\n$/, ""));
    return cleanedLines.join("\n");
  }

  if (tableCodeCell) {
    return tableCodeCell.textContent.trim();
  }

  return codeBlock.textContent.trim();
}

window.addEventListener("DOMContentLoaded", (event) => {
  document.querySelectorAll(".highlight-wrapper").forEach((highlightWrapper) => createCopyButton(highlightWrapper));
});
