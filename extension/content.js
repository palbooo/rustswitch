const inject = document.createElement("script");
inject.src = chrome.runtime.getURL("catcher.js");
inject.onload = function () {
  this.remove();
};
(document.head || document.documentElement).appendChild(inject);

// Change the login button and description
const button = document.querySelector(
  "body > div > div > div.overlay-buttons > form > button > span"
);
const description = document.querySelector(
  "body > div > div > div.overlay-body > p"
);
if (button && description) {
  button.innerHTML = "Login to copy Auth Data";
  description.style.color = "blue";
  description.innerHTML = "Click login to copy your Rust+ authentication data.";
}

// Create notification element
const notification = document.createElement("div");
notification.style.position = "fixed";
notification.style.top = "20px";
notification.style.right = "20px";
notification.style.backgroundColor = "#4CAF50";
notification.style.color = "white";
notification.style.padding = "16px";
notification.style.borderRadius = "4px";
notification.style.display = "none";
notification.style.zIndex = "10000";
notification.innerHTML = "Auth data copied to clipboard!";
document.body.appendChild(notification);

// Listen for auth data
window.addEventListener("message", function (event) {
  if (event.data && event.data.type === "RUST_AUTH_DATA") {
    // Copy to clipboard
    const textToCopy = JSON.stringify(event.data.authData, null, 2);
    navigator.clipboard.writeText(textToCopy).then(() => {
      // Show notification
      notification.style.display = "block";
      setTimeout(() => {
        notification.style.display = "none";
      }, 3000);
    });
  }
});
