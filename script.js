function verifyMessage() {

  const textInput = document.getElementById("messageInput");
  const linkInput = document.getElementById("linkInput");

  const text = textInput.value.toLowerCase().trim();
  const imageFile = document.getElementById("imageInput").files;
  const link = linkInput.value.trim();

  const loader = document.getElementById("loader");
  const resultBox = document.getElementById("result");
  const status = document.getElementById("status");
  const reason = document.getElementById("reason");
  const meter = document.getElementById("threatFill");

  resultBox.classList.add("hidden");
  status.innerText = "";
  reason.innerHTML = "";
  meter.style.width = "0%";

  loader.classList.remove("hidden");

  setTimeout(() => {

    if (text === "" && imageFile.length === 0 && link === "") {
      loader.classList.add("hidden");
      resultBox.classList.remove("hidden");

      status.innerText = "INVALID INPUT";
      status.className ="invalid";
      reason.innerHTML = "<b>Please enter message, image or valid link.</b>";
      return;
    }

    if (text !== "") {

      let scamScore = 0;
      let scamReasons = [];

      const urgencyWords = ["urgent","immediately","right now","jaldi","abhi","turant","warning"];
      const fearWords = ["account block","band ho jayega","suspend","freeze","legal action","penalty"];
      const financialWords = ["bank","account","otp","payment","upi","transaction","pin"];
      const authorityWords = ["rbi","bank manager","government","income tax"];
      const rewardWords = ["free","reward","gift","win","cashback","offer"];
      const manipulationWords = ["forward","share","send to","viral"];

      urgencyWords.forEach(word => { if (text.includes(word)) { scamScore += 1; scamReasons.push("Urgency pressure"); } });
      fearWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Fear language"); } });
      financialWords.forEach(word => { if (text.includes(word)) { scamScore += 3; scamReasons.push("Financial targeting"); } });
      authorityWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Authority impersonation"); } });
      rewardWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Reward bait"); } });
      manipulationWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Forward manipulation"); } });

      loader.classList.add("hidden");
      resultBox.classList.remove("hidden");

      if (scamScore >= 7) {
        status.innerText = "SCAM DETECTED";
        status.className = "danger";

        let confidence = 70 + scamScore * 3;
        if (confidence > 95) confidence = 95;

        meter.style.width = confidence + "%";
        meter.style.background = "red";

        reason.innerHTML =
          "<h3>Social Engineering Attack</h3>" +
          "<b>AI Confidence:</b> " + confidence + "%<br>" +
          "<b>Risk Level:</b> HIGH<br><br>" +
          scamReasons.join("<br>");

        return;
      }

      else if (scamScore >= 4) {
        status.innerText = "SUSPICIOUS MESSAGE";
        status.className = "warning";

        let confidence = 60 + scamScore * 3;

        meter.style.width = confidence + "%";
        meter.style.background = "orange";

        reason.innerHTML =
          "<h3>Suspicious Behaviour</h3>" +
          "<b>AI Confidence:</b> " + confidence + "%<br>" +
          "<b>Risk Level:</b> MEDIUM<br><br>" +
          scamReasons.join("<br>");

        return;
      }

      else {
        status.innerText = "SAFE MESSAGE";
        status.className = "safe";

        meter.style.width = "20%";
        meter.style.background = "green";

        reason.innerHTML =
          "<h3>No threat patterns detected</h3>" +
          "<b>Risk Level:</b> LOW";

        return;
      }
    }

    if (imageFile.length > 0) {

      const file = imageFile[0];
      const validTypes = ["image/png","image/jpeg","image/jpg","image/webp"];

      if (!validTypes.includes(file.type)) {
        loader.classList.add("hidden");
        resultBox.classList.remove("hidden");

        status.innerText = "INVALID IMAGE";
        status.className = "invalid";
        reason.innerHTML = "<b>Upload valid screenshot image only.</b>";
        return;
      }

      checkImageWithBackend(file, status, reason, meter, loader, resultBox);
      return;
    }

    if (link !== "") {

      const urlPattern = /^(https?:\/\/)?([\w\-]+\.)+[a-z]{2,}(\/.*)?$/i;

      if (!urlPattern.test(link)) {
        loader.classList.add("hidden");
        resultBox.classList.remove("hidden");

        status.innerText = "INVALID LINK";
        status.className = "invalid";
        reason.innerHTML = "<b>Enter proper website or news URL.</b>";
        return;
      }

      checkLinkWithBackend(link, status, reason, meter, loader, resultBox);
      return;
    }

  }, 1200);
}


async function checkLinkWithBackend(link, status, reason, meter, loader, resultBox) {

  try {

    const response = await fetch("http://127.0.0.1:5000/check_link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ link: link })
    });

    const data = await response.json();

    loader.classList.add("hidden");
    resultBox.classList.remove("hidden");

    status.innerText = data.verdict;

    let aiConfidence = data.confidence;

    meter.style.width = aiConfidence + "%";

    if (data.verdict === "PHISHING") {
      meter.style.background = "red";
      status.className = "danger";
    }
    else if (data.verdict === "SUSPICIOUS") {
      meter.style.background = "orange";
      status.className = "warning";
    }
    else {
      meter.style.background = "green";
      status.className = "safe";
    }

    // professional reasons formatting
let reasonsHTML = "";

if (data.reasons && data.reasons.length > 0) {
  reasonsHTML = "<ul>";
  data.reasons.forEach(r => {
    reasonsHTML += "<li>" + r + "</li>";
  });
  reasonsHTML += "</ul>";
} else {
  reasonsHTML = "<p>No suspicious signals detected.</p>";
}

reason.innerHTML =
  "<div class='analysis-block'>" +
  "<h3>Link Security Analysis</h3>" +

  "<div class='analysis-grid'>" +

  "<div><b>Verdict:</b> " + data.verdict + "</div>" +
  "<div><b>AI Confidence:</b> " + aiConfidence + "%</div>" +
  "<div><b>Risk Level:</b> " + data.verdict + "</div>" +

  "</div>" +

  "<b>Detection Factors:</b>" +
  reasonsHTML +

  "</div>";
  } 
  
  catch (error) {

    loader.classList.add("hidden");
    resultBox.classList.remove("hidden");

    status.innerText = "BACKEND ERROR";
    status.className = "invalid";
    reason.innerHTML = "<b>Server connection failed.</b>";
  }
}
async function checkImageWithBackend(file, status, reason, meter, loader, resultBox) {

  try {

    const formData = new FormData();
    formData.append("image", file);

    const response = await fetch("http://127.0.0.1:5000/check_image", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    loader.classList.add("hidden");
    resultBox.classList.remove("hidden");

    if (data.error) {
      status.innerText = "IMAGE SCAN FAILED";
      status.className = "invalid";
      reason.innerHTML = "<b>Unable to analyze image.</b>";
      return;
    }

    status.innerText = data.verdict;

    let aiConfidence = data.confidence;
    meter.style.width = aiConfidence + "%";

    if (data.verdict.includes("FAKE")) {
      meter.style.background = "red";
      status.className = "danger";
    }
    else if (data.verdict.includes("SUSPICIOUS")) {
      meter.style.background = "orange";
      status.className = "warning";
    }
    else {
      meter.style.background = "green";
      status.className = "safe";
    }

    // reasons formatting
    let reasonsHTML = "";

    if (data.reasons && data.reasons.length > 0) {
      reasonsHTML = "<ul>";
      data.reasons.forEach(r => {
        reasonsHTML += "<li>" + r + "</li>";
      });
      reasonsHTML += "</ul>";
    } else {
      reasonsHTML = "<p>No anomalies detected.</p>";
    }

    reason.innerHTML =
      "<div class='analysis-block'>" +
      "<h3>Payment Screenshot Analysis</h3>" +

      "<div class='analysis-grid'>" +
      "<div><b>Verdict:</b> " + data.verdict + "</div>" +
      "<div><b>AI Confidence:</b> " + aiConfidence + "%</div>" +
      "<div><b>Risk Level:</b> " + data.verdict + "</div>" +
      "</div>" +

      "<b>Detection Factors:</b>" +
      reasonsHTML +

      "</div>";

  } catch (error) {

    loader.classList.add("hidden");
    resultBox.classList.remove("hidden");

    status.innerText = "BACKEND ERROR";
    status.className = "invalid";
    reason.innerHTML = "<b>Image scan server failed.</b>";
  }
}
