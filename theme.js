/* Runs before first paint: follow Cockpit's light/dark setting (dark is the default palette). */
(function () {
    var s; try { s = localStorage.getItem("shell:style"); } catch (e) {}
    s = s || "auto";
    var dark = s === "dark" || (s === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    if (!dark) document.documentElement.classList.add("light");
})();
