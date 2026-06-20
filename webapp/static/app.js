const form = document.querySelector("#predict-form");
const payloadInput = document.querySelector("#payload");
const thresholdInput = document.querySelector("#threshold");
const submitButton = document.querySelector("#submit-button");
const resultCard = document.querySelector("#result-card");
const attackProb = document.querySelector("#attack-prob");
const normalProb = document.querySelector("#normal-prob");
const inputLength = document.querySelector("#input-length");
const normalizedPayload = document.querySelector("#normalized-payload");
const errorMessage = document.querySelector("#error-message");

function formatPercent(value) {
  return `${(value * 100).toFixed(2)}%`;
}

function setLoading(isLoading) {
  submitButton.disabled = isLoading;
  submitButton.textContent = isLoading ? "Đang phân loại..." : "Phân loại";
}

function showError(message) {
  errorMessage.textContent = message;
  resultCard.className = "result-card empty";
  resultCard.querySelector(".result-label").textContent = "Không thể phân loại";
  resultCard.querySelector(".result-main").textContent = "Backend trả về lỗi";
}

function showResult(result) {
  const isAttack = result.label === 1;
  errorMessage.textContent = "";
  resultCard.className = `result-card ${isAttack ? "attack" : "normal"}`;
  resultCard.querySelector(".result-label").textContent = `Threshold ${result.threshold}`;
  resultCard.querySelector(".result-main").textContent = isAttack
    ? "Attack request"
    : "Normal request";
  attackProb.textContent = formatPercent(result.attack_probability);
  normalProb.textContent = formatPercent(result.normal_probability);
  inputLength.textContent = `${result.input_length}${result.truncated ? ` / truncated to ${result.max_len}` : ""}`;
  normalizedPayload.textContent = result.normalized_payload || "-";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoading(true);

  try {
    const response = await fetch("/api/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        payload: payloadInput.value,
        threshold: Number(thresholdInput.value),
      }),
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Request failed.");
    }
    showResult(data.result);
  } catch (error) {
    showError(error.message);
  } finally {
    setLoading(false);
  }
});
