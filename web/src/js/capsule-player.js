// The player inside a downloaded time capsule: one offline HTML file holding a
// reel and the map's own code. Concatenated after map.js and reel.js by the
// server, so their names are in scope here.
(() => {
  const reel = JSON.parse(document.getElementById("reel-data").textContent);
  if (!reel.graph?.nodes?.length) return;
  const box = document.getElementById("player");
  box.hidden = false;
  const map = new LivingMap(document.getElementById("player-map"), {
    onSelect: (id) => {
      const n = reel.graph.nodes.find((x) => x.id === id);
      const info = document.getElementById("player-info");
      info.textContent = n ? `${n.label}${n.sub ? ` · ${n.sub}` : ""}` : "";
    },
  });
  map.setTheme(matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  map.show(reel.graph, { spanMS: reel.step * 10 });
  const head = document.getElementById("player-head");
  const when = document.getElementById("player-when");
  const play = document.getElementById("player-play");
  const speed = document.getElementById("player-speed");
  head.min = reel.from; head.max = reel.to; head.step = 1000; head.value = reel.to;
  const lookback = Math.max(reel.step * 5, Math.min(reel.to - reel.from, 300_000));
  const seek = (t) => {
    head.value = t;
    when.textContent = new Date(t).toISOString().replace("T", " ").slice(0, 19) + "Z";
    map.applyFrame(reelFrame(reel, t, lookback), lookback);
  };
  head.oninput = () => seek(Number(head.value));
  let playing = false, last = 0;
  const tick = (now) => {
    if (!playing) return;
    let t = Number(head.value) + (now - last) * Number(speed.value);
    last = now;
    if (t >= reel.to) t = reel.from;
    seek(t);
    requestAnimationFrame(tick);
  };
  play.onclick = () => {
    playing = !playing;
    play.textContent = playing ? "❚❚" : "▶";
    if (playing) {
      if (Number(head.value) >= reel.to) head.value = reel.from;
      last = performance.now();
      requestAnimationFrame(tick);
    }
  };
  // Open on the last moment anything happened: a window's tail is often quiet,
  // and a capsule that opens on an empty map looks broken.
  let lastStep = -1;
  for (const s of reel.series) lastStep = Math.max(lastStep, s.points[s.points.length - 1]?.[0] ?? -1);
  seek(lastStep >= 0 ? Math.min(reel.from + (lastStep + 1) * reel.step, reel.to) : reel.to);
})();
