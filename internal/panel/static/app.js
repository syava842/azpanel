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

	// Страницы с автообновлением (задача, «Сейчас», обновления) перезагружаются
	// целиком: место прокрутки страницы и журналов сохраняется перед
	// перезагрузкой и восстанавливается после. Журнал, прокрученный до конца,
	// остаётся в конце и показывает новые строки.
	var scrollKey = "azpanel-scroll:" + location.pathname + location.search;
	function autoRefresh() {
		if (document.querySelector('meta[http-equiv="refresh"]')) return true;
		var box = document.querySelector("[data-autorefresh]");
		return !!(box && box.checked);
	}
	function saveScroll() {
		if (!autoRefresh()) return;
		var logs = [];
		var els = document.querySelectorAll("pre.log");
		for (var i = 0; i < els.length; i++) {
			var el = els[i];
			logs.push({ top: el.scrollTop, end: el.scrollTop + el.clientHeight >= el.scrollHeight - 4 });
		}
		try {
			sessionStorage.setItem(scrollKey, JSON.stringify({ y: window.scrollY, logs: logs }));
		} catch (e) { /* без хранилища — прокрутка сбросится, как раньше */ }
	}
	function restoreScroll() {
		var els = document.querySelectorAll("pre.log");
		var saved = null;
		try { saved = JSON.parse(sessionStorage.getItem(scrollKey) || "null"); } catch (e) { saved = null; }
		for (var i = 0; i < els.length; i++) {
			var s = saved && saved.logs && saved.logs[i];
			// Впервые — с конца: там самое свежее.
			els[i].scrollTop = !s || s.end ? els[i].scrollHeight : s.top;
		}
		if (saved && typeof saved.y === "number") window.scrollTo(0, saved.y);
	}
	window.addEventListener("pagehide", saveScroll);
	window.addEventListener("beforeunload", saveScroll);

	document.addEventListener("DOMContentLoaded", function () {
		restoreScroll();
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

		localTimes();
		tableToggles();
	});

	function getPref(k) {
		try { return localStorage.getItem(k); } catch (e) { return null; }
	}
	function setPref(k, v) {
		try { localStorage.setItem(k, v); } catch (e) { /* без хранилища — до перезагрузки */ }
	}

	// <time datetime="…" data-local> — время в часовом поясе браузера; без
	// скриптов остаётся текст в UTC.
	function localTimes() {
		var els = document.querySelectorAll("time[data-local]");
		for (var i = 0; i < els.length; i++) {
			var d = new Date(els[i].getAttribute("datetime"));
			if (isNaN(d.getTime())) continue;
			els[i].textContent = d.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
			els[i].title = d.toISOString().replace("T", " ").replace(".000Z", " UTC");
		}
	}

	// «Показать IP» (скрыть адреса, например для снимка экрана) и
	// «Автообновление» таблиц: выбор запоминается в браузере.
	function tableToggles() {
		var ipBox = document.querySelector("[data-toggle-ip]");
		if (ipBox) {
			ipBox.checked = getPref("azpanel-hide-ip") !== "1";
			root.classList.toggle("hide-ip", !ipBox.checked);
			ipBox.addEventListener("change", function () {
				root.classList.toggle("hide-ip", !ipBox.checked);
				setPref("azpanel-hide-ip", ipBox.checked ? "0" : "1");
			});
		}
		var arBox = document.querySelector("[data-autorefresh]");
		if (arBox) {
			var sec = parseInt(arBox.getAttribute("data-autorefresh"), 10) || 15;
			var timer = null;
			var arm = function () {
				if (timer) window.clearTimeout(timer);
				timer = arBox.checked ? window.setTimeout(function () { location.reload(); }, sec * 1000) : null;
			};
			arBox.checked = getPref("azpanel-autorefresh") !== "0";
			arm();
			arBox.addEventListener("change", function () {
				setPref("azpanel-autorefresh", arBox.checked ? "1" : "0");
				arm();
			});
		}
	}
})();
