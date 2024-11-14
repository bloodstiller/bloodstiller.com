(() => {
  // ns-hugo:/home/martin/Dropbox/40-49_Career/44-Blog/bloodstiller/themes/hugo-liftoff/assets/js/components/switchTheme.js
  function switchTheme() {
    let themeSwitch = document.getElementById("themeSwitch");
    if (themeSwitch) {
      let initTheme = function() {
        let lsItem = localStorage.getItem("themeSwitch");
        let darkThemeSelected = false;
        if (lsItem !== null) {
          darkThemeSelected = lsItem === "dark";
        } else {
          darkThemeSelected = window.matchMedia("(prefers-color-scheme: dark)").matches;
        }
        themeSwitch.checked = darkThemeSelected;
        resetTheme();
      }, resetTheme = function() {
        if (themeSwitch.checked) {
          document.body.setAttribute("data-theme", "dark");
          localStorage.setItem("themeSwitch", "dark");
        } else {
          document.body.removeAttribute("data-theme");
          localStorage.setItem("themeSwitch", "light");
        }
        if (typeof DISQUS !== "undefined") {
          DISQUS.reset({ reload: true });
        }
      };
      initTheme();
      themeSwitch.addEventListener("change", () => {
        resetTheme();
      });
    }
  }
  var switcher = (() => {
    switchTheme();
  })();

  // ns-hugo:/home/martin/Dropbox/40-49_Career/44-Blog/bloodstiller/themes/hugo-liftoff/assets/js/components/clipboard.js
  var addCopyButtons = (clipboard2) => {
    document.querySelectorAll(".highlight > pre > code").forEach((codeBlock) => {
      const button = document.createElement("button");
      const svgCopy = '<svg role="img" aria-hidden="true" aria-labelledby="clipboardCopy" height="16" viewBox="0 0 16 16" version="1.1" width="16" data-view-component="true"><title id="clipboardCopy">Copy the code snippet contents</title><path fill-rule="evenodd" d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 010 1.5h-1.5a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-1.5a.75.75 0 011.5 0v1.5A1.75 1.75 0 019.25 16h-7.5A1.75 1.75 0 010 14.25v-7.5z"></path><path fill-rule="evenodd" d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0114.25 11h-7.5A1.75 1.75 0 015 9.25v-7.5zm1.75-.25a.25.25 0 00-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 00.25-.25v-7.5a.25.25 0 00-.25-.25h-7.5z"></path></svg>';
      const svgCheck = '<svg role="img" aria-hidden="true" aria-labelledby="clipboardCheckmark" height="16" viewBox="0 0 16 16" version="1.1" width="16" data-view-component="true"><title id="clipboardCheckmark">Code snippet contents copied</title><path fill-rule="evenodd" fill="rgb(63, 185, 80)" d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"></path></svg>';
      button.className = "clipboard-button";
      button.type = "button";
      button.innerHTML = svgCopy;
      button.addEventListener("click", () => {
        let textToCopy = "";
        let codeBlockChildren = Array.from(codeBlock.children);
        codeBlockChildren.forEach(function(span) {
          textToCopy += span.lastChild.innerText;
        });
        clipboard2.writeText(textToCopy).then(
          () => {
            button.blur();
            button.innerHTML = svgCheck;
            setTimeout(() => button.innerHTML = svgCopy, 2e3);
          },
          (error) => button.innerHTML = "Error"
        );
      });
      const pre = codeBlock.parentNode;
      pre.parentNode.insertBefore(button, pre);
    });
  };
  var clipboard = (() => {
    if (navigator && navigator.clipboard) {
      addCopyButtons(navigator.clipboard);
    }
  })();

  // ns-hugo:/home/martin/Dropbox/40-49_Career/44-Blog/bloodstiller/themes/hugo-liftoff/assets/js/components/toc.js
  var toggleToc = (() => {
    let tocToggle = document.getElementById("js-toc-toggle");
    let tocContents = document.getElementById("js-toc-contents");
    if (tocToggle) {
      tocToggle.addEventListener("click", () => {
        tocContents.classList.toggle("toc-contents--active");
      });
    }
  })();

  // ns-hugo:/home/martin/Dropbox/40-49_Career/44-Blog/bloodstiller/themes/hugo-liftoff/assets/js/layouts/header.js
  function toggleNav() {
    let mainMenu = document.getElementById("js-menu");
    let navBarToggle = document.getElementById("js-navbar-toggle");
    navBarToggle.addEventListener("click", () => {
      mainMenu.classList.toggle("menu--active");
      removeSubMenus();
    });
  }
  function toggleMobileMenu() {
    let menuItems = document.querySelectorAll(".menu-item");
    menuItems.forEach(function(item) {
      item.addEventListener("click", () => {
        let subMenu = item.querySelector(".sub-menu");
        if (subMenu.classList.contains("sub-menu--active")) {
          subMenu.classList.remove("sub-menu--active");
        } else {
          removeSubMenus();
          subMenu.classList.add("sub-menu--active");
        }
      });
    });
  }
  function removeSubMenus() {
    let subMenus = document.querySelectorAll(".sub-menu");
    subMenus.forEach(function(sub) {
      if (sub.classList.contains("sub-menu--active")) {
        sub.classList.remove("sub-menu--active");
      }
    });
  }
  var header = (() => {
    toggleNav();
    toggleMobileMenu();
  })();

  // ns-hugo:/home/martin/Dropbox/40-49_Career/44-Blog/bloodstiller/themes/hugo-liftoff/assets/js/pages/home.js
  function filterPosts() {
    let selectPosts = document.getElementById("select-posts");
    let entries = document.querySelectorAll(".post-entry-filter");
    if (selectPosts) {
      selectPosts.addEventListener("change", () => {
        entries.forEach(function(entry) {
          if (entry.classList.contains(`entry--${selectPosts.value}`) | selectPosts.value === "all-posts") {
            entry.style.display = "block";
          } else {
            entry.style.display = "none";
          }
        });
      });
    }
  }
  var home = (() => {
    filterPosts();
  })();
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsibnMtaHVnbzovaG9tZS9tYXJ0aW4vRHJvcGJveC80MC00OV9DYXJlZXIvNDQtQmxvZy9ibG9vZHN0aWxsZXIvdGhlbWVzL2h1Z28tbGlmdG9mZi9hc3NldHMvanMvY29tcG9uZW50cy9zd2l0Y2hUaGVtZS5qcyIsICJucy1odWdvOi9ob21lL21hcnRpbi9Ecm9wYm94LzQwLTQ5X0NhcmVlci80NC1CbG9nL2Jsb29kc3RpbGxlci90aGVtZXMvaHVnby1saWZ0b2ZmL2Fzc2V0cy9qcy9jb21wb25lbnRzL2NsaXBib2FyZC5qcyIsICJucy1odWdvOi9ob21lL21hcnRpbi9Ecm9wYm94LzQwLTQ5X0NhcmVlci80NC1CbG9nL2Jsb29kc3RpbGxlci90aGVtZXMvaHVnby1saWZ0b2ZmL2Fzc2V0cy9qcy9jb21wb25lbnRzL3RvYy5qcyIsICJucy1odWdvOi9ob21lL21hcnRpbi9Ecm9wYm94LzQwLTQ5X0NhcmVlci80NC1CbG9nL2Jsb29kc3RpbGxlci90aGVtZXMvaHVnby1saWZ0b2ZmL2Fzc2V0cy9qcy9sYXlvdXRzL2hlYWRlci5qcyIsICJucy1odWdvOi9ob21lL21hcnRpbi9Ecm9wYm94LzQwLTQ5X0NhcmVlci80NC1CbG9nL2Jsb29kc3RpbGxlci90aGVtZXMvaHVnby1saWZ0b2ZmL2Fzc2V0cy9qcy9wYWdlcy9ob21lLmpzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvLyBBZGFwdGVkIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL0NvZHlIb3VzZS9kYXJrLWxpZ2h0LW1vZGUtc3dpdGNoXG5cbmZ1bmN0aW9uIHN3aXRjaFRoZW1lKCkge1xuICBsZXQgdGhlbWVTd2l0Y2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGhlbWVTd2l0Y2gnKTtcbiAgaWYgKHRoZW1lU3dpdGNoKSB7XG4gICAgaW5pdFRoZW1lKCk7XG5cbiAgICB0aGVtZVN3aXRjaC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7XG4gICAgICByZXNldFRoZW1lKCk7XG4gICAgfSk7XG5cbiAgICBmdW5jdGlvbiBpbml0VGhlbWUoKSB7XG4gICAgICBsZXQgbHNJdGVtID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3RoZW1lU3dpdGNoJyk7XG4gICAgICBsZXQgZGFya1RoZW1lU2VsZWN0ZWQgPSBmYWxzZTtcbiAgICAgIGlmIChsc0l0ZW0gIT09IG51bGwpIHtcbiAgICAgICAgZGFya1RoZW1lU2VsZWN0ZWQgPSBsc0l0ZW0gPT09ICdkYXJrJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRhcmtUaGVtZVNlbGVjdGVkID0gd2luZG93Lm1hdGNoTWVkaWEoJyhwcmVmZXJzLWNvbG9yLXNjaGVtZTogZGFyayknKS5tYXRjaGVzO1xuICAgICAgfVxuXG4gICAgICB0aGVtZVN3aXRjaC5jaGVja2VkID0gZGFya1RoZW1lU2VsZWN0ZWQ7XG4gICAgICByZXNldFRoZW1lKCk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcmVzZXRUaGVtZSgpIHtcbiAgICAgIGlmICh0aGVtZVN3aXRjaC5jaGVja2VkKSB7XG4gICAgICAgIGRvY3VtZW50LmJvZHkuc2V0QXR0cmlidXRlKCdkYXRhLXRoZW1lJywgJ2RhcmsnKTtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3RoZW1lU3dpdGNoJywgJ2RhcmsnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQXR0cmlidXRlKCdkYXRhLXRoZW1lJyk7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCd0aGVtZVN3aXRjaCcsICdsaWdodCcpO1xuICAgICAgfVxuXG4gICAgICAvLyBSZXNldCBEaXNxdXMgdG8gbWF0Y2ggbmV3IGNvbG9yIHNjaGVtZVxuICAgICAgaWYgKHR5cGVvZiBESVNRVVMgIT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgICBESVNRVVMucmVzZXQoeyByZWxvYWQ6IHRydWUgfSk7XG4gICAgICB9XG4gICAgfVxuICB9XG59XG5cbmNvbnN0IHN3aXRjaGVyID0gKCgpID0+IHtcbiAgc3dpdGNoVGhlbWUoKTtcbn0pKCk7XG5cbmV4cG9ydCB7IHN3aXRjaGVyIH07IiwgIi8vIEFkYXB0ZWQgZnJvbSB0aGUgZm9sbG93aW5nIHR1dG9yaWFsczpcbi8vIGh0dHBzOi8vd3d3LmRhbm55Z3VvLmNvbS9ibG9nL2hvdy10by1hZGQtY29weS10by1jbGlwYm9hcmQtYnV0dG9ucy10by1jb2RlLWJsb2Nrcy1pbi1odWdvL1xuLy8gaHR0cHM6Ly9hYXJvbmx1bmEuZGV2L2Jsb2cvYWRkLWNvcHktYnV0dG9uLXRvLWNvZGUtYmxvY2tzLWh1Z28tY2hyb21hL1xuLy8gaHR0cHM6Ly9sb2dmZXRjaC5jb20vaHVnby1hZGQtY29weS10by1jbGlwYm9hcmQtYnV0dG9uL1xuXG5jb25zdCBhZGRDb3B5QnV0dG9ucyA9IChjbGlwYm9hcmQpID0+IHtcbiAgLy8gMS4gTG9vayBmb3IgcHJlID4gY29kZSBlbGVtZW50cyBpbiB0aGUgRE9NXG4gIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5oaWdobGlnaHQgPiBwcmUgPiBjb2RlJykuZm9yRWFjaCgoY29kZUJsb2NrKSA9PiB7XG4gICAgLy8gMi4gQ3JlYXRlIGEgYnV0dG9uIHRoYXQgd2lsbCB0cmlnZ2VyIGEgY29weSBvcGVyYXRpb25cbiAgICBjb25zdCBidXR0b24gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTtcbiAgICBjb25zdCBzdmdDb3B5ID0gJzxzdmcgcm9sZT1cImltZ1wiIGFyaWEtaGlkZGVuPVwidHJ1ZVwiIGFyaWEtbGFiZWxsZWRieT1cImNsaXBib2FyZENvcHlcIiBoZWlnaHQ9XCIxNlwiIHZpZXdCb3g9XCIwIDAgMTYgMTZcIiB2ZXJzaW9uPVwiMS4xXCIgd2lkdGg9XCIxNlwiIGRhdGEtdmlldy1jb21wb25lbnQ9XCJ0cnVlXCI+PHRpdGxlIGlkPVwiY2xpcGJvYXJkQ29weVwiPkNvcHkgdGhlIGNvZGUgc25pcHBldCBjb250ZW50czwvdGl0bGU+PHBhdGggZmlsbC1ydWxlPVwiZXZlbm9kZFwiIGQ9XCJNMCA2Ljc1QzAgNS43ODQuNzg0IDUgMS43NSA1aDEuNWEuNzUuNzUgMCAwMTAgMS41aC0xLjVhLjI1LjI1IDAgMDAtLjI1LjI1djcuNWMwIC4xMzguMTEyLjI1LjI1LjI1aDcuNWEuMjUuMjUgMCAwMC4yNS0uMjV2LTEuNWEuNzUuNzUgMCAwMTEuNSAwdjEuNUExLjc1IDEuNzUgMCAwMTkuMjUgMTZoLTcuNUExLjc1IDEuNzUgMCAwMTAgMTQuMjV2LTcuNXpcIj48L3BhdGg+PHBhdGggZmlsbC1ydWxlPVwiZXZlbm9kZFwiIGQ9XCJNNSAxLjc1QzUgLjc4NCA1Ljc4NCAwIDYuNzUgMGg3LjVDMTUuMjE2IDAgMTYgLjc4NCAxNiAxLjc1djcuNUExLjc1IDEuNzUgMCAwMTE0LjI1IDExaC03LjVBMS43NSAxLjc1IDAgMDE1IDkuMjV2LTcuNXptMS43NS0uMjVhLjI1LjI1IDAgMDAtLjI1LjI1djcuNWMwIC4xMzguMTEyLjI1LjI1LjI1aDcuNWEuMjUuMjUgMCAwMC4yNS0uMjV2LTcuNWEuMjUuMjUgMCAwMC0uMjUtLjI1aC03LjV6XCI+PC9wYXRoPjwvc3ZnPic7XG4gICAgY29uc3Qgc3ZnQ2hlY2sgPSAnPHN2ZyByb2xlPVwiaW1nXCIgYXJpYS1oaWRkZW49XCJ0cnVlXCIgYXJpYS1sYWJlbGxlZGJ5PVwiY2xpcGJvYXJkQ2hlY2ttYXJrXCIgaGVpZ2h0PVwiMTZcIiB2aWV3Qm94PVwiMCAwIDE2IDE2XCIgdmVyc2lvbj1cIjEuMVwiIHdpZHRoPVwiMTZcIiBkYXRhLXZpZXctY29tcG9uZW50PVwidHJ1ZVwiPjx0aXRsZSBpZD1cImNsaXBib2FyZENoZWNrbWFya1wiPkNvZGUgc25pcHBldCBjb250ZW50cyBjb3BpZWQ8L3RpdGxlPjxwYXRoIGZpbGwtcnVsZT1cImV2ZW5vZGRcIiBmaWxsPVwicmdiKDYzLCAxODUsIDgwKVwiIGQ9XCJNMTMuNzggNC4yMmEuNzUuNzUgMCAwMTAgMS4wNmwtNy4yNSA3LjI1YS43NS43NSAwIDAxLTEuMDYgMEwyLjIyIDkuMjhhLjc1Ljc1IDAgMDExLjA2LTEuMDZMNiAxMC45NGw2LjcyLTYuNzJhLjc1Ljc1IDAgMDExLjA2IDB6XCI+PC9wYXRoPjwvc3ZnPic7XG4gICAgYnV0dG9uLmNsYXNzTmFtZSA9ICdjbGlwYm9hcmQtYnV0dG9uJztcbiAgICBidXR0b24udHlwZSA9ICdidXR0b24nO1xuICAgIGJ1dHRvbi5pbm5lckhUTUwgPSBzdmdDb3B5O1xuICAgIGJ1dHRvbi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHtcbiAgICAgIGxldCB0ZXh0VG9Db3B5ID0gJyc7XG4gICAgICBsZXQgY29kZUJsb2NrQ2hpbGRyZW4gPSBBcnJheS5mcm9tKGNvZGVCbG9jay5jaGlsZHJlbilcbiAgICAgIGNvZGVCbG9ja0NoaWxkcmVuLmZvckVhY2goZnVuY3Rpb24oc3Bhbikge1xuICAgICAgICAvLyBsYXN0Q2hpbGQgaXMgcmVxdWlyZWQgdG8gYXZvaWQgY29weWluZyBsaW5lIG51bWJlcnNcbiAgICAgICAgdGV4dFRvQ29weSArPSBzcGFuLmxhc3RDaGlsZC5pbm5lclRleHQ7XG4gICAgICB9KTtcbiAgICAgIGNsaXBib2FyZC53cml0ZVRleHQodGV4dFRvQ29weSkudGhlbihcbiAgICAgICAgKCkgPT4ge1xuICAgICAgICAgIGJ1dHRvbi5ibHVyKCk7XG4gICAgICAgICAgYnV0dG9uLmlubmVySFRNTCA9IHN2Z0NoZWNrO1xuICAgICAgICAgIHNldFRpbWVvdXQoKCkgPT4gKGJ1dHRvbi5pbm5lckhUTUwgPSBzdmdDb3B5KSwgMjAwMCk7XG4gICAgICAgIH0sXG4gICAgICAgIChlcnJvcikgPT4gKGJ1dHRvbi5pbm5lckhUTUwgPSAnRXJyb3InKVxuICAgICAgKTtcbiAgICB9KTtcbiAgICAvLyAzLiBBcHBlbmQgdGhlIGJ1dHRvbiBkaXJlY3RseSBiZWZvcmUgdGhlIHByZSB0YWdcbiAgICBjb25zdCBwcmUgPSBjb2RlQmxvY2sucGFyZW50Tm9kZTtcbiAgICBwcmUucGFyZW50Tm9kZS5pbnNlcnRCZWZvcmUoYnV0dG9uLCBwcmUpO1xuICB9KTtcbn07XG5cbmNvbnN0IGNsaXBib2FyZCA9ICgoKSA9PiB7XG4gIGlmIChuYXZpZ2F0b3IgJiYgbmF2aWdhdG9yLmNsaXBib2FyZCkge1xuICAgIGFkZENvcHlCdXR0b25zKG5hdmlnYXRvci5jbGlwYm9hcmQpO1xuICB9XG59KSgpO1xuXG5leHBvcnQgeyBjbGlwYm9hcmQgfTsiLCAiY29uc3QgdG9nZ2xlVG9jID0gKCgpID0+IHtcbiAgbGV0IHRvY1RvZ2dsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdqcy10b2MtdG9nZ2xlJyk7XG4gIGxldCB0b2NDb250ZW50cyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdqcy10b2MtY29udGVudHMnKTtcblxuICBpZiAodG9jVG9nZ2xlKSB7XG4gICAgdG9jVG9nZ2xlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgICAgdG9jQ29udGVudHMuY2xhc3NMaXN0LnRvZ2dsZSgndG9jLWNvbnRlbnRzLS1hY3RpdmUnKTtcbiAgICB9KTtcbiAgfVxufSkoKTtcblxuZXhwb3J0IHsgdG9nZ2xlVG9jIH07IiwgIi8vIFNob3cgb3IgaGlkZSBuYXYgb24gY2xpY2sgb2YgbWVudSBidXJnZXJcbmZ1bmN0aW9uIHRvZ2dsZU5hdigpIHtcbiAgbGV0IG1haW5NZW51ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2pzLW1lbnUnKTtcbiAgbGV0IG5hdkJhclRvZ2dsZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdqcy1uYXZiYXItdG9nZ2xlJyk7XG5cbiAgbmF2QmFyVG9nZ2xlLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4ge1xuICAgIG1haW5NZW51LmNsYXNzTGlzdC50b2dnbGUoJ21lbnUtLWFjdGl2ZScpO1xuICAgIHJlbW92ZVN1Yk1lbnVzKCk7XG4gIH0pO1xufVxuXG4vLyBTaG93IG9yIGhpZGUgbWVudSBpdGVtcyBvbiBtb2JpbGVcbmZ1bmN0aW9uIHRvZ2dsZU1vYmlsZU1lbnUoKSB7XG4gIGxldCBtZW51SXRlbXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcubWVudS1pdGVtJyk7XG5cbiAgbWVudUl0ZW1zLmZvckVhY2goZnVuY3Rpb24oaXRlbSkge1xuICAgIGl0ZW0uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7XG4gICAgICBsZXQgc3ViTWVudSA9IGl0ZW0ucXVlcnlTZWxlY3RvcignLnN1Yi1tZW51Jyk7XG4gICAgICBpZiAoc3ViTWVudS5jbGFzc0xpc3QuY29udGFpbnMoJ3N1Yi1tZW51LS1hY3RpdmUnKSkge1xuICAgICAgICBzdWJNZW51LmNsYXNzTGlzdC5yZW1vdmUoJ3N1Yi1tZW51LS1hY3RpdmUnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJlbW92ZVN1Yk1lbnVzKCk7XG4gICAgICAgIHN1Yk1lbnUuY2xhc3NMaXN0LmFkZCgnc3ViLW1lbnUtLWFjdGl2ZScpO1xuICAgICAgfVxuICAgIH0pO1xuICB9KTtcbn1cblxuLy8gQ29sbGFwc2Ugc3VibWVudXNcbmZ1bmN0aW9uIHJlbW92ZVN1Yk1lbnVzKCkge1xuICBsZXQgc3ViTWVudXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcuc3ViLW1lbnUnKTtcbiAgc3ViTWVudXMuZm9yRWFjaChmdW5jdGlvbihzdWIpIHtcbiAgICBpZiAoc3ViLmNsYXNzTGlzdC5jb250YWlucygnc3ViLW1lbnUtLWFjdGl2ZScpKSB7XG4gICAgICBzdWIuY2xhc3NMaXN0LnJlbW92ZSgnc3ViLW1lbnUtLWFjdGl2ZScpO1xuICAgIH1cbiAgfSk7XG59XG5cbmNvbnN0IGhlYWRlciA9ICgoKSA9PiB7XG4gIHRvZ2dsZU5hdigpO1xuICB0b2dnbGVNb2JpbGVNZW51KCk7XG59KSgpO1xuXG5leHBvcnQgeyBoZWFkZXIgfTsiLCAiZnVuY3Rpb24gZmlsdGVyUG9zdHMoKSB7XG4gIGxldCBzZWxlY3RQb3N0cyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZWxlY3QtcG9zdHMnKTtcbiAgbGV0IGVudHJpZXMgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcucG9zdC1lbnRyeS1maWx0ZXInKTtcbiAgaWYgKHNlbGVjdFBvc3RzKSB7XG4gICAgc2VsZWN0UG9zdHMuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgKCkgPT4ge1xuICAgICAgZW50cmllcy5mb3JFYWNoKGZ1bmN0aW9uKGVudHJ5KSB7XG4gICAgICAgIGlmIChlbnRyeS5jbGFzc0xpc3QuY29udGFpbnMoYGVudHJ5LS0ke3NlbGVjdFBvc3RzLnZhbHVlfWApIHwgc2VsZWN0UG9zdHMudmFsdWUgPT09ICdhbGwtcG9zdHMnKSB7XG4gICAgICAgICAgZW50cnkuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgZW50cnkuc3R5bGUuZGlzcGxheSA9ICdub25lJztcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cbn1cblxuY29uc3QgaG9tZSA9ICgoKSA9PiB7XG4gIGZpbHRlclBvc3RzKCk7XG59KSgpO1xuXG5leHBvcnQgeyBob21lIH07Il0sCiAgIm1hcHBpbmdzIjogIjs7QUFFQSxXQUFTLGNBQWM7QUFDckIsUUFBSSxjQUFjLFNBQVMsZUFBZSxhQUFhO0FBQ3ZELFFBQUksYUFBYTtBQU9mLFVBQVMsWUFBVCxXQUFxQjtBQUNuQixZQUFJLFNBQVMsYUFBYSxRQUFRLGFBQWE7QUFDL0MsWUFBSSxvQkFBb0I7QUFDeEIsWUFBSSxXQUFXLE1BQU07QUFDbkIsOEJBQW9CLFdBQVc7QUFBQSxRQUNqQyxPQUFPO0FBQ0wsOEJBQW9CLE9BQU8sV0FBVyw4QkFBOEIsRUFBRTtBQUFBLFFBQ3hFO0FBRUEsb0JBQVksVUFBVTtBQUN0QixtQkFBVztBQUFBLE1BQ2IsR0FFUyxhQUFULFdBQXNCO0FBQ3BCLFlBQUksWUFBWSxTQUFTO0FBQ3ZCLG1CQUFTLEtBQUssYUFBYSxjQUFjLE1BQU07QUFDL0MsdUJBQWEsUUFBUSxlQUFlLE1BQU07QUFBQSxRQUM1QyxPQUFPO0FBQ0wsbUJBQVMsS0FBSyxnQkFBZ0IsWUFBWTtBQUMxQyx1QkFBYSxRQUFRLGVBQWUsT0FBTztBQUFBLFFBQzdDO0FBR0EsWUFBSSxPQUFPLFdBQVcsYUFBYTtBQUMvQixpQkFBTyxNQUFNLEVBQUUsUUFBUSxLQUFLLENBQUM7QUFBQSxRQUNqQztBQUFBLE1BQ0Y7QUFoQ0EsZ0JBQVU7QUFFVixrQkFBWSxpQkFBaUIsVUFBVSxNQUFNO0FBQzNDLG1CQUFXO0FBQUEsTUFDYixDQUFDO0FBQUEsSUE2Qkg7QUFBQSxFQUNGO0FBRUEsTUFBTSxZQUFZLE1BQU07QUFDdEIsZ0JBQVk7QUFBQSxFQUNkLEdBQUc7OztBQ3RDSCxNQUFNLGlCQUFpQixDQUFDQSxlQUFjO0FBRXBDLGFBQVMsaUJBQWlCLHlCQUF5QixFQUFFLFFBQVEsQ0FBQyxjQUFjO0FBRTFFLFlBQU0sU0FBUyxTQUFTLGNBQWMsUUFBUTtBQUM5QyxZQUFNLFVBQVU7QUFDaEIsWUFBTSxXQUFXO0FBQ2pCLGFBQU8sWUFBWTtBQUNuQixhQUFPLE9BQU87QUFDZCxhQUFPLFlBQVk7QUFDbkIsYUFBTyxpQkFBaUIsU0FBUyxNQUFNO0FBQ3JDLFlBQUksYUFBYTtBQUNqQixZQUFJLG9CQUFvQixNQUFNLEtBQUssVUFBVSxRQUFRO0FBQ3JELDBCQUFrQixRQUFRLFNBQVMsTUFBTTtBQUV2Qyx3QkFBYyxLQUFLLFVBQVU7QUFBQSxRQUMvQixDQUFDO0FBQ0QsUUFBQUEsV0FBVSxVQUFVLFVBQVUsRUFBRTtBQUFBLFVBQzlCLE1BQU07QUFDSixtQkFBTyxLQUFLO0FBQ1osbUJBQU8sWUFBWTtBQUNuQix1QkFBVyxNQUFPLE9BQU8sWUFBWSxTQUFVLEdBQUk7QUFBQSxVQUNyRDtBQUFBLFVBQ0EsQ0FBQyxVQUFXLE9BQU8sWUFBWTtBQUFBLFFBQ2pDO0FBQUEsTUFDRixDQUFDO0FBRUQsWUFBTSxNQUFNLFVBQVU7QUFDdEIsVUFBSSxXQUFXLGFBQWEsUUFBUSxHQUFHO0FBQUEsSUFDekMsQ0FBQztBQUFBLEVBQ0g7QUFFQSxNQUFNLGFBQWEsTUFBTTtBQUN2QixRQUFJLGFBQWEsVUFBVSxXQUFXO0FBQ3BDLHFCQUFlLFVBQVUsU0FBUztBQUFBLElBQ3BDO0FBQUEsRUFDRixHQUFHOzs7QUN6Q0gsTUFBTSxhQUFhLE1BQU07QUFDdkIsUUFBSSxZQUFZLFNBQVMsZUFBZSxlQUFlO0FBQ3ZELFFBQUksY0FBYyxTQUFTLGVBQWUsaUJBQWlCO0FBRTNELFFBQUksV0FBVztBQUNiLGdCQUFVLGlCQUFpQixTQUFTLE1BQU07QUFDeEMsb0JBQVksVUFBVSxPQUFPLHNCQUFzQjtBQUFBLE1BQ3JELENBQUM7QUFBQSxJQUNIO0FBQUEsRUFDRixHQUFHOzs7QUNSSCxXQUFTLFlBQVk7QUFDbkIsUUFBSSxXQUFXLFNBQVMsZUFBZSxTQUFTO0FBQ2hELFFBQUksZUFBZSxTQUFTLGVBQWUsa0JBQWtCO0FBRTdELGlCQUFhLGlCQUFpQixTQUFTLE1BQU07QUFDM0MsZUFBUyxVQUFVLE9BQU8sY0FBYztBQUN4QyxxQkFBZTtBQUFBLElBQ2pCLENBQUM7QUFBQSxFQUNIO0FBR0EsV0FBUyxtQkFBbUI7QUFDMUIsUUFBSSxZQUFZLFNBQVMsaUJBQWlCLFlBQVk7QUFFdEQsY0FBVSxRQUFRLFNBQVMsTUFBTTtBQUMvQixXQUFLLGlCQUFpQixTQUFTLE1BQU07QUFDbkMsWUFBSSxVQUFVLEtBQUssY0FBYyxXQUFXO0FBQzVDLFlBQUksUUFBUSxVQUFVLFNBQVMsa0JBQWtCLEdBQUc7QUFDbEQsa0JBQVEsVUFBVSxPQUFPLGtCQUFrQjtBQUFBLFFBQzdDLE9BQU87QUFDTCx5QkFBZTtBQUNmLGtCQUFRLFVBQVUsSUFBSSxrQkFBa0I7QUFBQSxRQUMxQztBQUFBLE1BQ0YsQ0FBQztBQUFBLElBQ0gsQ0FBQztBQUFBLEVBQ0g7QUFHQSxXQUFTLGlCQUFpQjtBQUN4QixRQUFJLFdBQVcsU0FBUyxpQkFBaUIsV0FBVztBQUNwRCxhQUFTLFFBQVEsU0FBUyxLQUFLO0FBQzdCLFVBQUksSUFBSSxVQUFVLFNBQVMsa0JBQWtCLEdBQUc7QUFDOUMsWUFBSSxVQUFVLE9BQU8sa0JBQWtCO0FBQUEsTUFDekM7QUFBQSxJQUNGLENBQUM7QUFBQSxFQUNIO0FBRUEsTUFBTSxVQUFVLE1BQU07QUFDcEIsY0FBVTtBQUNWLHFCQUFpQjtBQUFBLEVBQ25CLEdBQUc7OztBQ3pDSCxXQUFTLGNBQWM7QUFDckIsUUFBSSxjQUFjLFNBQVMsZUFBZSxjQUFjO0FBQ3hELFFBQUksVUFBVSxTQUFTLGlCQUFpQixvQkFBb0I7QUFDNUQsUUFBSSxhQUFhO0FBQ2Ysa0JBQVksaUJBQWlCLFVBQVUsTUFBTTtBQUMzQyxnQkFBUSxRQUFRLFNBQVMsT0FBTztBQUM5QixjQUFJLE1BQU0sVUFBVSxTQUFTLFVBQVUsWUFBWSxLQUFLLEVBQUUsSUFBSSxZQUFZLFVBQVUsYUFBYTtBQUMvRixrQkFBTSxNQUFNLFVBQVU7QUFBQSxVQUN4QixPQUFPO0FBQ0wsa0JBQU0sTUFBTSxVQUFVO0FBQUEsVUFDeEI7QUFBQSxRQUNGLENBQUM7QUFBQSxNQUNILENBQUM7QUFBQSxJQUNIO0FBQUEsRUFDRjtBQUVBLE1BQU0sUUFBUSxNQUFNO0FBQ2xCLGdCQUFZO0FBQUEsRUFDZCxHQUFHOyIsCiAgIm5hbWVzIjogWyJjbGlwYm9hcmQiXQp9Cg==
