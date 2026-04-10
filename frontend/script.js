const socket = io();

const MAX_REQUESTS = 200;
const requests = [];
let deviceRows = [];
let pendingDefaultInterface = "";

const interfaceSelect = document.getElementById("interfaceSelect");
const domainFilter = document.getElementById("domainFilter");
const deviceFilter = document.getElementById("deviceFilter");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const refreshBtn = document.getElementById("refreshBtn");
const scanBtn = document.getElementById("scanBtn");
const statusText = document.getElementById("statusText");
const permissionWarning = document.getElementById("permissionWarning");
const limitationNote = document.getElementById("limitationNote");
const requestTableBody = document.getElementById("requestTableBody");
const deviceTableBody = document.getElementById("deviceTableBody");
const tableWrap = document.getElementById("tableWrap");
const searchInput = document.getElementById("searchInput");
const topDevicesList = document.getElementById("topDevicesList");
const popularDomainsList = document.getElementById("popularDomainsList");

function debounce(callback, delay = 150) {
  let timer = null;
  return (...args) => {
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(() => callback(...args), delay);
  };
}

const debouncedRenderRequests = debounce(() => renderRequests(), 120);
const debouncedRenderDevices = debounce(() => {
  renderDevices();
  populateDeviceFilter();
}, 160);

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.style.color = isError ? "#b83a2e" : "#6a7679";
}

function updateInterfaceDropdown(interfaces) {
  const previousValue = interfaceSelect.value;
  interfaceSelect.innerHTML = "";

  if (!interfaces.length) {
    const option = document.createElement("option");
    option.textContent = "No interfaces found";
    option.value = "";
    interfaceSelect.appendChild(option);
    return;
  }

  interfaces.forEach((iface) => {
    const option = document.createElement("option");
    option.value = iface.capture || iface.name;
    const label = iface.display || iface.name;
    option.textContent = `${label} (${iface.ip})`;
    interfaceSelect.appendChild(option);
  });

  const allValues = interfaces.map((iface) => iface.capture || iface.name);
  if (previousValue && allValues.includes(previousValue)) {
    interfaceSelect.value = previousValue;
    return;
  }

  const selected =
    allValues.includes(pendingDefaultInterface) && pendingDefaultInterface
      ? pendingDefaultInterface
      : allValues[0];
  if (selected) {
    interfaceSelect.value = selected;
  }
}

function renderTopDevices(items) {
  topDevicesList.innerHTML = "";

  if (!items.length) {
    topDevicesList.innerHTML = '<li class="muted">No device activity yet.</li>';
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("li");
    row.textContent = `${item.ip}  •  ${item.total_requests} requests`;
    topDevicesList.appendChild(row);
  });
}

function renderPopularDomains(items) {
  popularDomainsList.innerHTML = "";

  if (!items.length) {
    popularDomainsList.innerHTML = '<li class="muted">No domains captured yet.</li>';
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("li");
    row.textContent = `${item.domain}  •  ${item.count}`;
    if (item.count >= 4) {
      row.classList.add("hot");
    }
    popularDomainsList.appendChild(row);
  });
}

function renderDevices() {
  deviceTableBody.innerHTML = "";

  if (!deviceRows.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="7" class="muted">No devices observed yet.</td>';
    deviceTableBody.appendChild(row);
    return;
  }

  deviceRows.forEach((device) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${device.ip}</td>
      <td>${device.name || "Unknown Device"}</td>
      <td>${device.mac || "Unknown"}</td>
      <td>${device.total_requests}</td>
      <td>${device.unique_domains}</td>
      <td>${device.last_domain}</td>
      <td>${device.last_seen}</td>
    `;
    deviceTableBody.appendChild(row);
  });
}

function populateDeviceFilter() {
  const selectedValue = deviceFilter.value || "ALL";
  deviceFilter.innerHTML = '<option value="ALL">ALL</option>';

  deviceRows.forEach((device) => {
    const option = document.createElement("option");
    option.value = device.ip;
    option.textContent = `${device.name || "Unknown Device"} (${device.ip})`;
    deviceFilter.appendChild(option);
  });

  const options = Array.from(deviceFilter.options).map((opt) => opt.value);
  deviceFilter.value = options.includes(selectedValue) ? selectedValue : "ALL";
}

function addRequest(request) {
  requests.unshift(request);
  if (requests.length > MAX_REQUESTS) {
    requests.pop();
  }
  debouncedRenderRequests();
}

function renderRequests() {
  requestTableBody.innerHTML = "";

  const searchValue = searchInput.value.trim().toLowerCase();
  const selectedDevice = deviceFilter.value;

  requests
    .filter((request) => {
      if (selectedDevice !== "ALL" && request.device_ip !== selectedDevice) {
        return false;
      }

      if (!searchValue) return true;
      return (
        request.device_ip.toLowerCase().includes(searchValue) ||
        (request.device_name || "").toLowerCase().includes(searchValue) ||
        (request.raw_domain || "").toLowerCase().includes(searchValue) ||
        request.domain.toLowerCase().includes(searchValue) ||
        (request.readable_domain || "").toLowerCase().includes(searchValue)
      );
    })
    .forEach((request) => {
      const row = document.createElement("tr");
      if (request.popular) {
        row.classList.add("popular");
      }

      row.innerHTML = `
        <td>${request.timestamp || "--:--:--"}</td>
        <td>${request.device_ip}</td>
        <td>${request.device_name || "Unknown Device"}</td>
        <td>${request.device_mac || "Unknown"}</td>
        <td>${request.dst_ip}</td>
        <td>${request.raw_domain || request.domain}</td>
        <td>${request.readable_domain || request.domain}</td>
        <td>${request.protocol}</td>
        <td>${request.length}</td>
      `;

      requestTableBody.appendChild(row);
    });

  tableWrap.scrollTop = 0;
}

startBtn.addEventListener("click", () => {
  const selectedInterface = interfaceSelect.value;
  const selectedDomainFilter = domainFilter.value.trim();

  if (!selectedInterface) {
    setStatus("Please select a network interface.", true);
    return;
  }

  socket.emit("start_capture", {
    interface: selectedInterface,
    domainFilter: selectedDomainFilter,
  });
});

stopBtn.addEventListener("click", () => {
  socket.emit("stop_capture");
});

refreshBtn.addEventListener("click", () => {
  socket.emit("refresh_interfaces");
});

scanBtn.addEventListener("click", () => {
  const selectedInterface = interfaceSelect.value;
  if (!selectedInterface) {
    setStatus("Select an interface before ARP scan.", true);
    return;
  }
  socket.emit("scan_devices", { interface: selectedInterface });
});

searchInput.addEventListener("input", () => {
  debouncedRenderRequests();
});

deviceFilter.addEventListener("change", () => {
  debouncedRenderRequests();
});

socket.on("interfaces", (interfaces) => {
  updateInterfaceDropdown(interfaces || []);
});

socket.on("default_interface", (payload) => {
  pendingDefaultInterface = payload.interface || "";
  const options = Array.from(interfaceSelect.options).map((opt) => opt.value);
  if (pendingDefaultInterface && options.includes(pendingDefaultInterface)) {
    interfaceSelect.value = pendingDefaultInterface;
  }
});

socket.on("permissions", (payload) => {
  if (payload.allowed) {
    permissionWarning.classList.add("hidden");
    permissionWarning.textContent = "";
    return;
  }

  permissionWarning.classList.remove("hidden");
  permissionWarning.textContent =
    "Admin/root permission may be required for sniffing. " + payload.message;
});

socket.on("history", (history) => {
  requests.splice(0, requests.length, ...(history || []).slice(0, MAX_REQUESTS));
  renderRequests();
});

socket.on("limitation_note", (payload) => {
  limitationNote.textContent = payload.text || "";
});

socket.on("device_snapshot", (snapshot) => {
  deviceRows = snapshot || [];
  debouncedRenderDevices();
});

socket.on("top_devices", (items) => {
  renderTopDevices(items || []);
});

socket.on("popular_domains", (items) => {
  renderPopularDomains(items || []);
});

socket.on("dns_request", (request) => {
  addRequest(request);
});

socket.on("capture_status", (result) => {
  setStatus(result.message || "Status updated.", result.status !== "ok");

  const isRunning = result.status === "ok" && result.message.includes("Started");
  if (isRunning) {
    startBtn.disabled = true;
    stopBtn.disabled = false;
  }

  if (result.message.toLowerCase().includes("stopped")) {
    startBtn.disabled = false;
    stopBtn.disabled = true;
  }
});

socket.on("scan_status", (result) => {
  setStatus(result.message || "Scan status updated.", result.status !== "ok");
});
