// background.js
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({
    url: "https://companion-rust.facepunch.com/login",
  });
});
