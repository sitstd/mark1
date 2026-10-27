document.addEventListener("DOMContentLoaded", () => {
  const dialog = document.querySelector("[data-lightbox-dialog]");
  const dialogImage = dialog?.querySelector("img");
  const closeButton = dialog?.querySelector(".lightbox-close");

  if (dialog && dialogImage) {
    document.querySelectorAll("[data-lightbox]").forEach((link) => {
      link.addEventListener("click", (event) => {
        event.preventDefault();
        dialogImage.src = link.href;
        dialogImage.alt = link.getAttribute("aria-label") || "Project preview";
        dialog.hidden = false;
        closeButton?.focus();
      });
    });
    const closeDialog = () => {
      dialog.hidden = true;
      dialogImage.removeAttribute("src");
    };
    closeButton?.addEventListener("click", closeDialog);
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeDialog();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !dialog.hidden) closeDialog();
    });
  }

  document.querySelectorAll("[data-course-filter]").forEach((select) => {
    select.addEventListener("change", () => {
      const url = new URL(window.location.href);
      if (select.value) url.searchParams.set("course", select.value);
      else url.searchParams.delete("course");
      window.location.assign(url);
    });
  });
});
