// Тема и мобильное меню. Подключается в <head> без defer: тема ставится до
// отрисовки страницы. Встроенные скрипты запрещены CSP, поэтому только так.
(function () {
	"use strict";
	var root = document.documentElement;
	var key = "azpanel-theme";

	function stored() {
		try { return localStorage.getItem(key); } catch (e) { return null; }
	}
	function apply(theme) {
		if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
		else root.removeAttribute("data-theme");
	}
	apply(stored());

	function current() {
		var t = root.getAttribute("data-theme");
		if (t) return t;
		return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
	}

	document.addEventListener("DOMContentLoaded", function () {
		var body = document.body;
		var toggle = document.querySelector("[data-toggle-nav]");

		var themeBtn = document.querySelector("[data-toggle-theme]");
		function syncTheme() {
			if (themeBtn) themeBtn.setAttribute("aria-pressed", current() === "dark" ? "true" : "false");
		}
		syncTheme();

		function setNav(open) {
			body.classList.toggle("nav-open", open);
			if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
			if (open) {
				var first = document.querySelector("#sidebar nav a");
				// Меню становится видимым после смены класса: фокус — следующим кадром.
				if (first) window.requestAnimationFrame(function () { first.focus(); });
			}
		}

		document.addEventListener("click", function (ev) {
			var el = ev.target.closest ? ev.target.closest("[data-toggle-theme],[data-toggle-nav],[data-close-nav]") : null;
			if (!el) return;
			if (el.hasAttribute("data-toggle-theme")) {
				var next = current() === "dark" ? "light" : "dark";
				apply(next);
				syncTheme();
				try { localStorage.setItem(key, next); } catch (e) { /* без хранилища — только до перезагрузки */ }
			} else if (el.hasAttribute("data-toggle-nav")) {
				setNav(!body.classList.contains("nav-open"));
			} else {
				setNav(false);
			}
		});
		document.addEventListener("keydown", function (ev) {
			if (ev.key === "Escape" && body.classList.contains("nav-open")) {
				setNav(false);
				if (toggle) toggle.focus();
			}
		});
	});
})();
