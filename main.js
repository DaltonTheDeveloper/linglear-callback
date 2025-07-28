function log(msg) {
  const status = document.getElementById("status");
  console.log(msg);
  status.innerText += "\n" + msg;
}

function generateVerifier(length = 64) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let result = '';
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

async function generateChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function handleLoginClick() {
  const verifier = generateVerifier();
  const challenge = await generateChallenge(verifier);
  sessionStorage.setItem("pkce_verifier", verifier);

  const domain = "us-east-13vk8oummo.auth.us-east-1.amazoncognito.com";
  const clientId = "6aucsq3lg5okj8tse6hileusna";
  const redirectUri = "https://daltonthedeveloper.github.io/linglear-callback/";
  const scopes = "openid email";

  const url = `https://${domain}/oauth2/authorize?` +
    `response_type=code&client_id=${clientId}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `scope=${encodeURIComponent(scopes)}&` +
    `code_challenge=${challenge}&code_challenge_method=S256`;

  window.location.href = url;
}

async function maybeHandleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const verifier = sessionStorage.getItem("pkce_verifier");

  if (!code) {
    log("Ready to login.");
    return;
  }

  if (!verifier) {
    log("❌ PKCE code_verifier not found in sessionStorage.");
    return;
  }

  log("🔄 Exchanging code for tokens...");

  try {
    const tokenRes = await fetch("https://us-east-13vk8oummo.auth.us-east-1.amazoncognito.com/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "7fbfdf71tao48nla0nt63oam7n",
        redirect_uri: "https://daltonthedeveloper.github.io/linglear-callback/",
        code_verifier: verifier,
        code: code
      })
    });

    const tokens = await tokenRes.json();
    console.log("🎁 Token response:", tokens);

    if (tokens.id_token) {
      log("✅ Login successful. Sending token to extension...");

      const extensionId = "agdbknoebcbbaegohkblhdcjcmlekdbe";
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.src = `chrome-extension://${extensionId}/callback.html#id_token=${tokens.id_token}`;
      document.body.appendChild(iframe);

      history.replaceState({}, document.title, "/linglear-callback/");
    } else {
      log("❌ Token exchange failed:\n" + JSON.stringify(tokens, null, 2));
    }
  } catch (err) {
    log("🔥 Token exchange error: " + err.message);
  }
}

document.getElementById("login").onclick = handleLoginClick;
maybeHandleCallback();
