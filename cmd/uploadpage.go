package cmd

// uploadPageHTML is the single self-contained page the upload server
// hands out: no external assets, works from a phone. It uploads one
// file per POST with the relative path in ?name= so folder uploads
// keep their structure, and shows the final (possibly _1-suffixed)
// name the server picked.
const uploadPageHTML = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>bsf upload</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; justify-content: center;
         font: 15px/1.5 system-ui, sans-serif; }
  main { width: min(680px, 94vw); margin: 4vh 0; }
  h1 { font-size: 1.2em; margin: 0 0 2px; }
  .sub { opacity: .7; font-size: .85em; margin-bottom: 16px; }
  #drop { border: 2px dashed rgba(127,127,127,.5); border-radius: 12px;
          padding: 34px 16px; text-align: center; transition: .15s; }
  #drop.over { border-color: inherit; background: rgba(127,127,127,.12); }
  .btns { margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }
  button { font: inherit; padding: 7px 14px; border-radius: 8px; cursor: pointer;
           border: 1px solid rgba(127,127,127,.5); background: rgba(127,127,127,.12); }
  #files { margin-top: 18px; }
  .row { padding: 7px 0; border-bottom: 1px solid rgba(127,127,127,.25); }
  .row .name { display: flex; justify-content: space-between; gap: 8px; }
  .row .name .saved { opacity: .75; word-break: break-all; text-align: right; }
  .bar { height: 5px; border-radius: 3px; background: rgba(127,127,127,.3);
         margin-top: 5px; overflow: hidden; }
  .bar > div { height: 100%; width: 0; background: #3b82f6; transition: .15s; }
  .row.err .bar > div { background: #ef4444; width: 100%; }
  .hint { margin-top: 20px; opacity: .6; font-size: .8em; word-break: break-all; }
  #lock { display: none; border: 2px dashed rgba(127,127,127,.5); border-radius: 12px;
          padding: 34px 16px; text-align: center; }
  #lock input { font: inherit; padding: 7px 10px; border-radius: 8px; width: 11ch;
                text-align: center; border: 1px solid rgba(127,127,127,.5); }
  body.locked #lock { display: block; }
  body.locked #drop, body.locked #files { display: none; }
</style>
</head>
<body>
<main>
  <h1>上传文件 / Upload files</h1>
  <div class="sub">保存到接收方当前目录，同名文件自动加 _1 / saved on the receiver, name clashes get a _1 suffix</div>

  <div id="lock">
    <div><b>请输入上传口令</b> / enter the upload token<br>
    <span class="sub">it is printed on the receiver's terminal</span></div>
    <div class="btns" style="justify-content:center">
      <input id="tok" autocomplete="off" autocapitalize="off" spellcheck="false">
      <button id="unlock">进入 / go</button>
    </div>
  </div>

  <div id="drop">
    <div><b>拖放文件或文件夹到这里</b><br><span class="sub">drag &amp; drop files or folders here</span></div>
    <div class="btns">
      <button onclick="document.getElementById('fp').click()">选择文件 / files…</button>
      <button onclick="document.getElementById('dp').click()">选择文件夹 / folder…</button>
    </div>
    <input type="file" id="fp" multiple hidden>
    <input type="file" id="dp" webkitdirectory hidden>
  </div>

  <div id="files"></div>
  <div class="hint" id="hint"></div>
</main>

<script>
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.search).get("t") || "";
if (token) {
  // a restart minted a new token: fall back to the input
  fetch("/check?t=" + encodeURIComponent(token)).then(r => {
    if (!r.ok) lockPage("口令已失效，请重新输入 / token stale, re-enter it");
  });
} else {
  lockPage();
}
function lockPage(note) {
  document.body.classList.add("locked");
  if (note) document.querySelector("#lock .sub").textContent = note;
}
$("unlock").onclick = () => {
  const v = $("tok").value.trim();
  if (v) location = "/?t=" + encodeURIComponent(v);
};
$("tok").onkeydown = e => { if (e.key == "Enter") $("unlock").onclick(); };

let totalBytes = 0, doneBytes = 0, count = 0;

function human(n) {
  if (n >= 1<<30) return (n/(1<<30)).toFixed(1) + " GiB";
  if (n >= 1<<20) return (n/(1<<20)).toFixed(1) + " MiB";
  if (n >= 1<<10) return (n/(1<<10)).toFixed(1) + " KiB";
  return n + " B";
}

function addRow(path, size) {
  const row = document.createElement("div");
  row.className = "row";
  row.innerHTML =
    '<div class="name"><span class="p"></span><span class="saved">' + human(size) + '</span></div>' +
    '<div class="bar"><div></div></div>';
  row.querySelector(".p").textContent = path;
  $("files").prepend(row);
  return {
    progress: f => { row.querySelector(".bar > div").style.width = (f*100).toFixed(1) + "%"; },
    done: saved => { row.querySelector(".saved").textContent = saved; row.querySelector(".bar > div").style.width = "100%"; },
    error: msg => { row.classList.add("err"); row.querySelector(".saved").textContent = msg; },
  };
}

function upload(path, file, row) {
  return new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/upload?name=" + encodeURIComponent(path) + "&t=" + encodeURIComponent(token));
    xhr.setRequestHeader("X-Upload-Token", token);
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        row.progress(e.loaded / e.total);
        $("hint").textContent = (doneBytes + e.loaded) + " / " + human(totalBytes) + " …";
      }
    };
    xhr.onload = () => {
      if (xhr.status == 201) {
        const r = JSON.parse(xhr.responseText);
        doneBytes += file.size;
        row.done(r.saved + " · " + human(r.size));
      } else {
        row.error("error " + xhr.status + ": " + xhr.responseText.trim());
      }
      resolve();
    };
    xhr.onerror = () => { row.error("network error"); resolve(); };
    xhr.send(file);
  });
}

async function queue(files) {
  if (!files.length) return;
  count += files.length;
  totalBytes += files.reduce((s, f) => s + f.file.size, 0);
  $("hint").textContent = "0 / " + human(totalBytes) + " …";
  for (const f of files) {
    const row = addRow(f.path, f.file.size);
    await upload(f.path, f.file, row);
  }
  $("hint").textContent = "done: " + count + " file(s), " + human(doneBytes) + " · 上传完成";
}

// picker inputs
$("fp").onchange = () => queue([...$("fp").files].map(f => ({file: f, path: f.name})));
$("dp").onchange = () => queue([...$("dp").files].map(f => ({file: f, path: f.webkitRelativePath || f.name})));

// drag & drop, folders included (entries api)
const drop = $("drop");
drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = async e => {
  e.preventDefault();
  drop.classList.remove("over");
  const items = [...(e.dataTransfer.items || [])];
  const viaEntries = items.map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (viaEntries.length) {
    const out = [];
    const walk = (entry, prefix) => new Promise(resolve => {
      if (entry.isFile) {
        entry.file(f => { out.push({file: f, path: prefix + f.name}); resolve(); }, resolve);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        const dir = prefix + entry.name + "/";
        const step = () => reader.readEntries(batch => {
          if (!batch.length) { resolve(); return; }
          Promise.all(batch.map(en => walk(en, dir))).then(step);
        }, resolve);
        step();
      } else resolve();
    });
    await Promise.all(viaEntries.map(en => walk(en, "")));
    queue(out);
  } else {
    queue([...e.dataTransfer.files].map(f => ({file: f, path: f.name})));
  }
};
</script>
</body>
</html>
`
