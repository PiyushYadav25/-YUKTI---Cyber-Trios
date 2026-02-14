function verifyMessage() {

  const text = document.getElementById("messageInput").value.toLowerCase();
  const imageFile = document.getElementById("imageInput").files;
  const link = document.getElementById("linkInput").value;

  const loader = document.getElementById("loader");
  const resultBox = document.getElementById("result");
  const status = document.getElementById("status");
  const reason = document.getElementById("reason");
  const meter = document.getElementById("threatFill");

  loader.classList.remove("hidden");
  resultBox.classList.add("hidden");

  setTimeout(() => {

    loader.classList.add("hidden");
    resultBox.classList.remove("hidden");

    // Empty check
    if (text === "" && imageFile.length === 0 && link === "") {
      status.innerText = "Invalid Input";
      status.className ="invalid";
      reason.innerText = "Please provide text, image or link.";
      meter.style.width = "0%";
      return;
    }

    // SOCIAL ENGINEERING TEXT AI
    if (text !== "") {

      let scamScore = 0;
      let scamReasons = [];

      const urgencyWords = ["urgent","immediately","right now","jaldi","abhi","turant","warning"];
      const fearWords = ["account block","band ho jayega","suspend","freeze","legal action","penalty"];
      const financialWords = ["bank","account","otp","payment","upi","transaction","pin","verify account"];
      const authorityWords = ["rbi","bank manager","government","income tax","whatsapp team","support team"];
      const rewardWords = ["free","reward","gift","win","cashback","offer","prize","jeet gaye"];
      const manipulationWords = ["forward","share","send to","sabko bhejo","10 logon ko","viral"];

      urgencyWords.forEach(word => { if (text.includes(word)) { scamScore += 1; scamReasons.push("Urgency pressure detected"); } });
      fearWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Fear / threat language"); } });
      financialWords.forEach(word => { if (text.includes(word)) { scamScore += 3; scamReasons.push("Financial targeting"); } });
      authorityWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Authority impersonation"); } });
      rewardWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Reward bait detected"); } });
      manipulationWords.forEach(word => { if (text.includes(word)) { scamScore += 2; scamReasons.push("Social forwarding manipulation"); } });

      if (scamScore >= 7) {
        status.innerText = "SCAM DETECTED";
        status.className = "suspicious";
        meter.style.width = "90%";
        meter.style.background = "red";
        reason.innerHTML =
          "<b>Threat Type:</b> Social Engineering Scam<br><br>" +
          "<b>AI Confidence:</b> 92%<br><br>" +
          "<b>Risk Level:</b> HIGH<br><br>" +
          "<b>Detection Reasons:</b><br>• " +
          scamReasons.join("<br>• ");
        return;
      }

      else if (scamScore >= 4) {
        status.innerText = "HIGH RISK MESSAGE";
        status.className = "link";
        meter.style.width = "65%";
        meter.style.background = "orange";
        reason.innerHTML =
          "<b>Threat Type:</b> Suspicious Behaviour<br><br>" +
          "<b>AI Confidence:</b> 75%<br><br>" +
          "<b>Risk Level:</b> MEDIUM<br><br>" +
          "<b>Detection Reasons:</b><br>• " +
          scamReasons.join("<br>• ");
        return;
      }
    }

    // IMAGE AI DETECTION
    if (imageFile.length > 0) {
      status.innerText = "Analyzing Image...";
      status.className = "link";
      reason.innerText = "Running AI forensic scan";
      checkImageWithBackend(imageFile[0], status, reason, meter);
      return;
    }

    // LINK AI DETECTION
    if (link !== "") {
      status.innerText = "Checking link...";
      status.className = "link";
      reason.innerText = "Analyzing link with AI engine.";
      checkLinkWithBackend(link, status, reason, meter);
      return;
    }

    // Default safe
    status.innerText = "SAFE";
    status.className = "real";
    reason.innerText = "No suspicious patterns detected.";
    meter.style.width = "20%";
    meter.style.background = "green";

  }, 1200);
}


// 🔗 LINK BACKEND FUNCTION

async function checkLinkWithBackend(link, status, reason, meter) {

  try {

    const response = await fetch("http://127.0.0.1:5000/check_link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ link: link })
    });

    const data = await response.json();

    status.innerText = data.verdict;

    let aiConfidence = Math.min(95, data.score * 10);

    let riskLevel = "LOW";
    if (data.score >= 9) riskLevel = "HIGH";
    else if (data.score >= 5) riskLevel = "MEDIUM";

    let percent = (data.score / 15) * 100;
    meter.style.width = percent + "%";

    if (data.score >= 9) meter.style.background = "red";
    else if (data.score >= 5) meter.style.background = "orange";
    else meter.style.background = "green";

    reason.innerHTML =
      "<b>Threat Type:</b> " + data.verdict + "<br><br>" +
      "<b>AI Confidence:</b> " + aiConfidence + "%<br><br>" +
      "<b>Risk Level:</b> " + riskLevel + "<br><br>" +
      "<b>Detection Reasons:</b><br>• " +
      data.reasons.join("<br>• ");

  } catch (error) {

    status.innerText = "Error";
    status.className = "invalid";
    reason.innerText = "Backend connection failed.";
    meter.style.width = "0%";
  }
}


// 🖼 IMAGE BACKEND FUNCTION

async function checkImageWithBackend(imageFile, status, reason, meter) {

  try {

    let formData = new FormData();
    formData.append("image", imageFile);

    const response = await fetch("http://127.0.0.1:5000/check_image", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    status.innerText = data.verdict;

    if (data.verdict.includes("FAKE")) status.className = "suspicious";
    else if (data.verdict.includes("SUSPICIOUS")) status.className = "link";
    else status.className = "real";

    let percent = (data.score / 8) * 100;
    meter.style.width = percent + "%";

    if (data.score >= 5) meter.style.background = "red";
    else if (data.score >= 3) meter.style.background = "orange";
    else meter.style.background = "green";

    reason.innerHTML =
      "<b>Threat Type:</b> Image Fraud Analysis<br><br>" +
      "<b>AI Confidence:</b> " + Math.min(95, data.score * 12) + "%<br><br>" +
      "<b>Risk Level:</b> " + data.verdict + "<br><br>" +
      "<b>Detection Reasons:</b><br>• " +
      data.reasons.join("<br>• ");

  } catch (error) {

    status.innerText = "Image analysis failed";
    status.className = "invalid";
    reason.innerText = "Backend connection error";
    meter.style.width = "0%";
  }
}
