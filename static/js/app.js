// Behaviours the Rails app gets from Turbo (data-turbo-confirm) and Stimulus (tabs controller).
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault()
    })
  })

  // Tabs: <button data-tab> is paired by index with <div data-panel>.
  document.querySelectorAll("[data-tabs]").forEach((root) => {
    const tabs = [...root.querySelectorAll("[data-tab]")]
    const panels = [...root.querySelectorAll("[data-panel]")]
    const show = (index) => {
      tabs.forEach((tab, i) => tab.setAttribute("aria-selected", i === index))
      panels.forEach((panel, i) => (panel.hidden = i !== index))
    }
    tabs.forEach((tab, i) => tab.addEventListener("click", () => show(i)))
    show(0)
  })
})
