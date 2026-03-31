// // /**
// //  * Web Based Security Analyzer — client helpers (globals)
// //  */

// // const STORAGE_KEY = "wbsa_last_scan";

// // function saveScanResult(payload) {
// //   sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
// // }

// // function loadScanResult() {
// //   const raw = sessionStorage.getItem(STORAGE_KEY);
// //   if (!raw) return null;
// //   try {
// //     return JSON.parse(raw);
// //   } catch {
// //     return null;
// //   }
// // }

// // function clearScanResult() {
// //   sessionStorage.removeItem(STORAGE_KEY);
// // }





// /**
//  Web Based Security Analyzer
// */

// const STORAGE_KEY = "wbsa_last_scan";

// function saveScanResult(payload) {
//   sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
// }

// function loadScanResult() {
//   const raw = sessionStorage.getItem(STORAGE_KEY);
//   if (!raw) return null;

//   try {
//     return JSON.parse(raw);
//   } catch (e) {
//     console.error("Invalid JSON in storage");
//     return null;
//   }
// }

// function clearScanResult() {
//   sessionStorage.removeItem(STORAGE_KEY);
// }


// /* =========================
//    RUN SCAN FUNCTION
// ========================= */

// async function startScan(url) {

//   try {

//     const response = await fetch("http://127.0.0.1:5000/scan", {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/json"
//       },
//       body: JSON.stringify({ url: url })
//     });

//     if (!response.ok) {
//       throw new Error("Server returned " + response.status);
//     }

//     const text = await response.text();

//     if (!text) {
//       throw new Error("Empty response from backend");
//     }

//     const data = JSON.parse(text);

//     saveScanResult(data);

//     window.location.href = "dashboard.html";

//   } catch (error) {

//     console.error("Scan error:", error);

//     alert("Scan failed: " + error.message);

//   }
// }







// const STORAGE_KEY = "wbsa_last_scan";

// function saveScanResult(payload) {
//   sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
// }

// function loadScanResult() {
//   const raw = sessionStorage.getItem(STORAGE_KEY);
//   if (!raw) return null;

//   try {
//     return JSON.parse(raw);
//   } catch (e) {
//     console.error("Invalid JSON in storage");
//     return null;
//   }
// }

// function clearScanResult() {
//   sessionStorage.removeItem(STORAGE_KEY);
// }

// /* =========================
//    RUN SCAN FUNCTION
// ========================= */

// async function startScan(url) {

//   try {

//     const response = await fetch("http://127.0.0.1:5000/scan", {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/json"
//       },
//       body: JSON.stringify({ url })
//     });

//     const data = await response.json();

//     if (!response.ok) {
//       throw new Error(data.error || "Scan failed");
//     }

//     saveScanResult(data);

//     window.location.href = "/dashboard.html";

//   } catch (error) {

//     console.error("Scan error:", error);
//     alert("Scan failed: " + error.message);

//   }
// }












const BACKEND_URL = "http://127.0.0.1:5000";

async function startScan(targetUrl) {
  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "<p>Scanning...</p>";

  try {
    const response = await fetch(`${BACKEND_URL}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: targetUrl }),
    });

    // Always parse JSON — app.py now guarantees JSON even on errors
    const data = await response.json();

    if (!response.ok || !data.success) {
      showError(data.error || "Scan failed. Check the backend logs.");
      return;
    }

    displayResults(data);

  } catch (err) {
    // This fires if the backend is completely unreachable (server not running)
    showError(`Cannot reach backend: ${err.message}. Is Flask running on port 5000?`);
  }
}

function displayResults(data) {
  const resultsDiv = document.getElementById("results");
  const { summary, vulnerabilities, modules } = data;

  resultsDiv.innerHTML = `
    <h2>Scan Results for: ${data.target}</h2>
    <p><strong>Score:</strong> ${summary.score}/100 &nbsp; <strong>Risk:</strong> ${summary.risk}</p>
    <p>Vulnerabilities found: ${summary.total_vulnerabilities} 
       (High: ${summary.high}, Medium: ${summary.medium}, Low: ${summary.low})</p>

    <h3>Modules</h3>
    <ul>
      ${modules.map(m => `<li>${m.name}: <b>${m.status}</b> (${m.findings} findings)</li>`).join("")}
    </ul>

    <h3>Vulnerabilities</h3>
    ${vulnerabilities.length === 0 
      ? "<p>No vulnerabilities found.</p>"
      : vulnerabilities.map(v => `
        <div class="vuln">
          <b>[${v.severity}] ${v.name}</b>
          <p>${v.description}</p>
          <p><em>Fix: ${v.recommendation}</em></p>
        </div>
      `).join("")}
  `;
}

function showError(message) {
  document.getElementById("results").innerHTML = `<p style="color:red;">Error: ${message}</p>`;
}

// Hook up your scan button
document.getElementById("scanBtn")?.addEventListener("click", () => {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return alert("Please enter a URL.");
  startScan(url);
});