/* attest — in-browser verifier (progressive enhancement only).
   The file is read locally with File.arrayBuffer() and handed to the Attest
   bundle. Nothing is uploaded, there is no fetch, and there is no telemetry. */
(function () {
  "use strict";

  var api = window.Attest;
  var input = document.getElementById("verify-file");
  var button = document.getElementById("verify-button");
  var status = document.getElementById("verify-status");
  var errorBox = document.getElementById("verify-error");
  var errorText = document.getElementById("verify-error-text");
  var summaryWrap = document.getElementById("verify-summary-wrap");
  var summary = document.getElementById("verify-summary");
  var output = document.getElementById("verify-output");
  var outputCode = document.getElementById("verify-output-code");
  var dropzone = document.getElementById("verify-drop");
  var chosen = null;

  if (!input || !button) return;

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function chip(label, modifier) {
    var el = document.createElement("span");
    el.className = modifier ? "chip " + modifier : "chip";
    el.textContent = label;
    return el;
  }

  function stateChip(state) {
    if (state === "valid") return "chip--ok";
    if (state === "invalid") return "chip--error";
    return "chip--warning";
  }

  function messageOf(error) {
    return error && error.message ? error.message : String(error);
  }

  function showError(message) {
    errorText.textContent = message;
    errorBox.hidden = false;
    status.setAttribute("data-tone", "error");
    status.textContent = message;
  }

  function clearError() {
    errorBox.hidden = true;
    status.removeAttribute("data-tone");
  }

  function nameOf(file) {
    return file && file.name ? file.name : "the file";
  }

  function render(asset, file) {
    clear(summary);
    summary.appendChild(chip(asset.state, stateChip(asset.state)));

    var manifests = asset.manifests || [];
    if (manifests.length > 0) {
      var last = manifests[manifests.length - 1];
      var signatureOk = !!last.signature && last.signature.valid === true;
      summary.appendChild(
        chip(
          "signature " + (signatureOk ? "valid" : "invalid"),
          signatureOk ? "chip--ok" : "chip--error"
        )
      );
      var binding = last.hardBinding ? last.hardBinding.status : "unknown";
      summary.appendChild(
        chip(
          "hard binding " + binding,
          binding === "matched" ? "chip--ok" : "chip--warning"
        )
      );
      summary.appendChild(chip("assertions " + last.assertions.length));
    }

    var report;
    try {
      report = api.formatReport(asset, { verbose: true });
    } catch (err) {
      report = api.formatJson(asset);
    }
    outputCode.textContent = report;
    summaryWrap.hidden = false;
    output.hidden = false;
    clearError();

    if (asset.state === "unsigned") {
      showError(
        "No Content Credentials were found in " +
          nameOf(file) +
          ". The file is not invalid, just unverified: anyone could have produced it."
      );
      return;
    }
    status.textContent = nameOf(file) + ": " + api.summarize(asset);
  }

  function verifyFile(file) {
    if (!file) {
      showError("Choose an image first.");
      return;
    }
    if (!api || typeof api.verifyBytes !== "function") {
      showError("The Attest bundle did not load, so this file cannot be verified.");
      return;
    }
    if (file.size === 0) {
      showError("That file is empty.");
      return;
    }
    clearError();
    status.textContent = "Reading " + nameOf(file) + " locally\u2026";
    file
      .arrayBuffer()
      .then(function (buffer) {
        return api.verifyBytes(new Uint8Array(buffer));
      })
      .then(function (asset) {
        render(asset, file);
      })
      .catch(function (error) {
        showError("Could not verify " + nameOf(file) + ": " + messageOf(error));
      });
  }

  input.addEventListener("change", function () {
    chosen = input.files && input.files.length > 0 ? input.files[0] : null;
    if (chosen) {
      clearError();
      status.textContent =
        nameOf(chosen) + " selected. The file stays on this machine.";
    }
  });

  button.addEventListener("click", function () {
    if (!chosen && input.files && input.files.length > 0) chosen = input.files[0];
    verifyFile(chosen);
  });

  if (dropzone) {
    ["dragenter", "dragover"].forEach(function (type) {
      dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        dropzone.classList.add("is-drag");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        dropzone.classList.remove("is-drag");
      });
    });
    dropzone.addEventListener("drop", function (event) {
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length > 0) {
        chosen = files[0];
        verifyFile(chosen);
      }
    });
  }
})();
