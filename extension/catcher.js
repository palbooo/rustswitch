setInterval(() => {
  if (window.ReactNativeWebView === undefined) {
    window.ReactNativeWebView = {
      postMessage: function (message) {
        const auth = JSON.parse(message);
        console.log(auth);

        // Send auth data to content script
        window.postMessage(
          {
            type: "RUST_AUTH_DATA",
            authData: {
              steamId: auth.SteamId,
              token: auth.Token,
            },
          },
          "*"
        );
      },
    };
  }
}, 500);
