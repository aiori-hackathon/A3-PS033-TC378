"use strict";
const $ = id => document.getElementById(id);
const labels = {latency: "Latency", traceroute: "Traceroute", health: "System health"};
const descriptions = {latency: "Round-trip time & packet loss", traceroute: "Network path & hops", health: "System status & resources"};
const stages = ["DNS signature", "Metadata", "Address", "TLS identity", "Access token", "Response"];
let config, currentRun = null, activeService = "latency", busy = false, operation = "";
function route() {
  const inLab = location.hash === "#lab";
  document.body.classList.toggle("in-lab", inLab);
  $("welcome").hidden = inLab; $("lab-view").hidden = !inLab;
  $("nav-welcome").setAttribute("aria-current", inLab ? "false" : "page");
  $("nav-lab").setAttribute("aria-current", inLab ? "page" : "false");
  document.querySelectorAll("svg.network-lines").forEach(svg => {
    if (inLab || document.body.classList.contains("motion-paused")) svg.pauseAnimations(); else svg.unpauseAnimations();
  });
  window.scrollTo(0, 0);
  $(inLab ? "lab-heading" : "welcome-heading").focus({preventScroll:true});
  document.dispatchEvent(new CustomEvent("viewchange", {detail:{inLab}}));
}
window.addEventListener("hashchange", route);
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
function setMotion(paused) {
  document.body.classList.toggle("motion-paused", paused);
  document.dispatchEvent(new CustomEvent("motionchange", {detail:{paused}}));
  $("motion").textContent = paused ? "Resume motion" : "Pause motion";
  $("motion").setAttribute("aria-pressed", String(paused));
  document.querySelectorAll("svg.network-lines").forEach(svg => paused || location.hash === "#lab" ? svg.pauseAnimations() : svg.unpauseAnimations());
}
setMotion(reducedMotion.matches);
$("motion").addEventListener("click", () => setMotion(!document.body.classList.contains("motion-paused")));
reducedMotion.addEventListener("change", event => setMotion(event.matches));
route();

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
function notice(text, state = "") { $("notice").textContent = text; $("notice").className = `notice ${state}`; }
function dataKind(result) {
  if (!result?.data) return "NO RESULT";
  return result.data.mock === false ? "LIVE SNAPSHOT" : result.data.mock === true ? "SAMPLE DATA" : "UNSPECIFIED";
}
function explainMode() {
  $("health-mode-description").textContent = $("health-mode").value === "live"
    ? "Health samples the diagnostic service's host once per accepted request. Latency and traceroute stay sample data."
    : "All three services return fixed sample data for a repeatable demonstration. No live system-health measurement is collected.";
}
function setBusy(next, action = "") {
  busy = next; operation = next ? action : "";
  document.body.classList.toggle("lab-busy", next && action === "run");
  for (const id of ["run", "browse-services", "service", "scenario", "health-mode"]) $(id).disabled = next || !config;
  $("export").disabled = next || !currentRun;
  $("run").textContent = next && action === "run" ? "Running laboratory…" : "Run discovery →";
  $("browse-services").textContent = next && action === "browse" ? "Browsing signed DNS…" : "Browse DNS services ↗";
  $("inventory-section")?.setAttribute("aria-busy", String(next && action === "browse"));
  renderCards();
}
async function apiRequest(path, body) {
  const response = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json", "X-Demo-Token": config.token}, body: JSON.stringify(body), signal: AbortSignal.timeout(30000)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The local server could not complete this request.");
  return data;
}
function errorMessage(error) {
  return error.name === "TimeoutError" ? "The request timed out. Wait a moment, then retry or restart the local server." : error.message || "Could not reach the local server. Start dashboard.py and refresh.";
}
function explainScenario() {
  if (!config) return;
  const scenario = $("scenario").value;
  $("scenario-description").textContent = config.scenarios[scenario].description;
  const singleFault = ["bogus", "malformed", "unavailable", "unauthorized"].includes(scenario);
  $("fault-note").textContent = singleFault && $("service").value === "all" ? "With all services selected, this fault targets latency. The other two act as a comparison." : "Every run starts a fresh lab with newly assigned local ports.";
}
function renderCards() {
  $("services").replaceChildren();
  for (const [index, [name, label]] of Object.entries(labels).entries()) {
    const result = currentRun?.results.find(r => r.service === name);
    const card = node("button", `service${name === activeService ? " active" : ""}`);
    card.type = "button";
    card.disabled = busy || (currentRun && !result);
    card.setAttribute("aria-pressed", String(name === activeService));
    const top = node("span", "service-top");
    top.append(node("strong", "", label), node("span", "service-index", `0${index + 1}`));
    const status = result ? result.status === "SUCCESS" ? dataKind(result) === "LIVE SNAPSHOT" ? "Live snapshot received" : dataKind(result) === "SAMPLE DATA" ? "Sample response received" : "Response received" : "Stopped" : operation === "run" ? "Running…" : "Not run";
    card.append(top, node("span", `status ${result ? result.status === "SUCCESS" ? "passed" : "failed" : ""}`, status), node("span", "service-description", result ? result.status : descriptions[name]));
    card.addEventListener("click", () => {activeService = name; renderCards(); renderDetail();});
    $("services").append(card);
  }
}
const lessons = {
  SUCCESS: ["The service was discovered and invoked.", "Signed DNS metadata supplied the endpoint. Its address, TLS identity and access token were checked before the response was accepted."],
  DNSSEC_BOGUS: ["The DNS signature could not be trusted.", "The client stopped before connecting to the service. Altered records and expired signatures must not be accepted as verified discovery."],
  DNSSEC_UNVERIFIED: ["An unsigned answer is not enough.", "The required signature was absent. The client refused to use the endpoint and did not send a service request."],
  METADATA_INVALID: ["A valid signature is only one check.", "The record was correctly signed, but its capability did not match the requested service. The client rejected the metadata before connecting."],
  AUTHENTICATION_DENIED: ["Discovery does not grant access.", "DNS and TLS verification passed. The service received a request but rejected its incorrect token; no diagnostic result was returned."],
  SERVICE_UNAVAILABLE: ["Discovery does not ensure availability.", "The client found and verified the DNS records, but could not connect to the offline endpoint. No service request was sent."],
  TLS_REJECTED: ["Endpoint identity must also be verified.", "DNS verification passed, but the TLS certificate was not trusted by the client. The client stopped before sending its access token."]
};
function uptime(seconds) {
  const whole = Math.max(0, Math.floor(seconds));
  const days = Math.floor(whole / 86400), hours = Math.floor(whole % 86400 / 3600), minutes = Math.floor(whole % 3600 / 60);
  return `${days ? `${days}d ` : ""}${hours}h ${minutes}m ${whole % 60}s`;
}
function renderHealthDetails(output, payload) {
  const data = payload.result, provenance = payload.provenance || {};
  const details = node("dl", "health-details");
  const fields = [
    ["Memory used / total", `${(data.memory_used_bytes / 1073741824).toFixed(2)} / ${(data.memory_total_bytes / 1073741824).toFixed(2)} GiB`],
    ["Memory available", `${(data.memory_available_bytes / 1073741824).toFixed(2)} GiB`],
    ["System uptime", uptime(data.uptime_seconds)],
    ["Measured at (UTC)", provenance.measured_at || "Not provided"],
    ["CPU sample window", `${Number(provenance.cpu_sample_seconds) * 1000} ms`]
  ];
  fields.forEach(([label, value]) => details.append(node("dt", "", label), node("dd", "", value)));
  output.append(details, node("p", "measurement-scope", "One snapshot from the diagnostic service's host via psutil. In Docker, these values can reflect the container's Linux host or VM; they are not guaranteed to be container-only usage. This is an observation, not a health verdict."));
}
function renderDetail() {
  const result = currentRun?.results.find(r => r.service === activeService);
  $("trace-heading").textContent = `${labels[activeService]} · verification path`;
  $("trace-time").textContent = result ? `${result.elapsed_ms.toFixed(2)} ms · client workflow` : "";
  $("trace-description").textContent = result ? (result.detail || `All checks passed. The service returned ${dataKind(result) === "LIVE SNAPSHOT" ? "a live measurement snapshot" : "a sample response"}.`) : "Each stage runs only if the previous checks allow it.";
  $("endpoint").textContent = result?.evidence.endpoint ? `Discovered endpoint: ${result.evidence.endpoint}` : result ? "No endpoint accepted from DNS." : "The endpoint will appear after DNS and metadata verification.";
  $("trace").replaceChildren();
  stages.forEach((label, i) => {
    const stage = result?.trace[i];
    const state = stage?.status || "not_run";
    const item = node("li", state);
    item.title = stage?.detail || "This stage has not run.";
    item.append(node("span", "stage-icon", state === "passed" ? "✓" : state === "failed" ? "!" : String(i + 1)), node("span", "stage-name", label), node("span", "stage-status", state === "passed" ? `Passed · ${stage.duration_ms.toFixed(1)} ms` : state === "failed" ? "Stopped here" : "Not run"));
    $("trace").append(item);
  });
  const output = $("diagnostic-output"); output.replaceChildren(); output.className = "output-placeholder";
  $("data-kind").textContent = dataKind(result);
  $("data-kind").classList.toggle("live-data", dataKind(result) === "LIVE SNAPSHOT");
  if (result?.data) {
    output.className = "";
    const data = result.data.result;
    if (activeService === "traceroute") {
      const hops = node("div", "hops"); data.hops.forEach((hop, i) => hops.append(node("div", "", `${String(i + 1).padStart(2, "0")}  →  ${hop}`))); output.append(hops);
    } else {
      const metrics = node("div", "metrics");
      const values = activeService === "latency" ? [[data.round_trip_ms, "ms", "Round-trip time"], [data.packet_loss_percent, "%", "Packet loss"]] : [[data.cpu_percent, "%", "CPU usage"], [data.memory_percent, "%", "Memory usage"]];
      for (const [value, unit, label] of values) { const metric = node("div", "metric"); const strong = node("strong", "", value); strong.append(node("small", "", ` ${unit}`)); metric.append(strong, node("span", "", label)); metrics.append(metric); }
      output.append(metrics);
      if (activeService === "health" && result.data.mock === false) renderHealthDetails(output, result.data);
      else if (data.status) output.append(node("p", "muted", `Sample system status: ${data.status}`));
    }
    if (result.data.mock === true) output.append(node("p", "measurement-scope", "Fixed sample data for this demonstration. These values were not measured on your laptop or network."));
  } else output.textContent = result ? result.invocation_attempted ? "The service request was attempted. No diagnostic response was accepted." : "No diagnostic request was sent. The workflow stopped earlier." : "An accepted service response appears here, labelled as live or sample data.";
  const lesson = result ? lessons[result.status] || ["The run could not complete.", result.detail || "Inspect the technical evidence for this run."] : ["Discovery and access are separate.", "A signed record tells the client where to connect. TLS checks the endpoint's identity. The service still decides whether to accept the caller's token."];
  $("lesson-title").textContent = lesson[0]; $("lesson-body").textContent = lesson[1];
  $("evidence-output").textContent = result ? JSON.stringify({run_id: currentRun.run_id, scenario: currentRun.scenario, dns_listener: `127.0.0.1:${currentRun.dns_port}`, published_record: currentRun.published_records.find(r => r.service === activeService)?.record, ...result}, null, 2) : "Run the lab to inspect its evidence.";
}
async function run() {
  if (busy || !config) return;
  const request = {scenario: $("scenario").value, service: $("service").value, health_mode: $("health-mode").value};
  currentRun = null;
  $("lab-view").classList.remove("result-enter");
  setBusy(true, "run"); $("summary").hidden = true;
  notice("Running real DNS queries and security checks. Results appear when this run completes.", "running");
  renderCards(); renderDetail();
  try {
    const data = await apiRequest("/api/run", request);
    currentRun = data; activeService = data.results[0].service;
    const passed = data.results.filter(r => r.status === "SUCCESS").length;
    const expected = data.results.every(r => r.matches_expected);
    const live = data.results.filter(r => r.status === "SUCCESS" && r.data?.mock === false).length;
    const sample = data.results.filter(r => r.status === "SUCCESS" && r.data?.mock === true).length;
    const kinds = [live ? `${live} live snapshot${live === 1 ? "" : "s"}` : "", sample ? `${sample} sample response${sample === 1 ? "" : "s"}` : ""].filter(Boolean).join("; ");
    notice(expected ? passed === data.results.length ? `${passed} of ${data.results.length} services returned results: ${kinds}. All checks passed.` : `Expected failure observed. ${data.results.length - passed} of ${data.results.length} service workflows stopped; ${passed} returned results${kinds ? ` (${kinds})` : ""}.` : "The outcome differs from this scenario's expectation. Inspect the result before presenting it.", expected ? passed === data.results.length ? "good" : "blocked" : "error");
    $("summary").replaceChildren(node("span", "", `RUN ${data.run_id}`), node("span", "", config.scenarios[data.scenario].label), node("span", "", `diag.test · DNS :${data.dns_port}`), node("span", "", `${data.duration_ms.toFixed(0)} ms including setup`));
    $("summary").hidden = false; $("export").disabled = false;
  } catch (error) { notice(errorMessage(error), "error"); }
  finally { setBusy(false); renderDetail(); if(currentRun) $("lab-view").classList.add("result-enter"); }
}
async function browseServices() {
  if (busy || !config) return;
  setBusy(true, "browse");
  $("inventory-list").replaceChildren(); $("inventory-summary").hidden = true; $("inventory-evidence").hidden = true; $("inventory-returned-scope").hidden = true;
  $("inventory-notice").textContent = "Querying the local service index and checking signed DNS metadata. No diagnostics will be invoked.";
  $("inventory-notice").className = "inventory-notice running";
  try {
    const data = await apiRequest("/api/inventory", {}), inventory = data.inventory;
    const verified = inventory.status === "VERIFIED";
    $("inventory-notice").textContent = verified ? "Service-index signature verified with the provisioned local key. The entries below report DNS metadata checks only; TLS and diagnostic invocation have not run." : `The service index was not accepted: ${inventory.status}. ${inventory.detail || "No trusted inventory is available."}`;
    $("inventory-notice").className = `inventory-notice ${verified ? "verified" : "rejected"}`;
    $("inventory-summary").replaceChildren(node("span", "", `ZONE ${data.zone}`), node("span", "", `DNS :${data.dns_port}`), node("span", "", `${data.duration_ms.toFixed(0)} ms including setup`), node("span", "", `Completed ${data.completed_at}`));
    $("inventory-summary").hidden = false;
    $("inventory-returned-scope").textContent = data.scope || "This response describes local catalogue metadata only.";
    $("inventory-returned-scope").hidden = false;
    for (const entry of inventory.entries || []) {
      const card = node("article", `inventory-entry ${entry.status === "READY" ? "ready" : "unavailable"}`);
      const title = node("div", "inventory-entry-title");
      title.append(node("h3", "", entry.service || entry.name), node("span", "inventory-status", entry.status === "READY" ? "DNS METADATA ACCEPTED" : entry.status));
      card.append(title, node("p", "mono inventory-name", entry.name), node("p", "", `Capability: ${entry.capability || "Not accepted"}`));
      if (entry.endpoint) card.append(node("p", "mono inventory-endpoint", entry.endpoint));
      if (entry.detail) card.append(node("p", "inventory-detail", entry.detail));
      card.append(node("p", "inventory-checks", "Catalogue endpoint · not running · TLS not checked · diagnostic not invoked"));
      $("inventory-list").append(card);
    }
    if (verified && !inventory.entries?.length) $("inventory-list").append(node("p", "muted", "The verified index published no service entries."));
    $("inventory-evidence-output").textContent = JSON.stringify(data, null, 2); $("inventory-evidence").hidden = false;
  } catch (error) { $("inventory-notice").textContent = errorMessage(error); $("inventory-notice").className = "inventory-notice rejected"; }
  finally { setBusy(false); }
}
$("run").addEventListener("click", run);
$("browse-services").addEventListener("click", browseServices);
$("health-mode").addEventListener("change", explainMode);
$("service").addEventListener("change", explainScenario);
$("scenario").addEventListener("change", explainScenario);
$("export").addEventListener("click", () => {
  if (!currentRun) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentRun, null, 2)], {type: "application/json"}));
  const link = node("a"); link.href = url; link.download = `PS033-${currentRun.scenario}-${currentRun.run_id}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
async function initialize() {
  renderCards(); renderDetail();
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Could not connect. Open the local URL printed by dashboard.py.");
    config = await response.json();
    $("scenario").replaceChildren();
    for (const [value, scenario] of Object.entries(config.scenarios)) {const option = node("option", "", scenario.label); option.value = value; $("scenario").append(option);}
    setBusy(false); $("connection").textContent = "Local server connected"; $("inventory-notice").textContent = "Ready to query the signed index. Browse to see the services actually published in the local zone."; explainScenario(); explainMode();
  } catch (error) { $("connection").textContent = "Disconnected"; notice(error.message, "error"); $("inventory-notice").textContent = "Could not connect to the local server. Refresh after starting the application."; $("inventory-notice").className = "inventory-notice rejected"; }
}
initialize();
