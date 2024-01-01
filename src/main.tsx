import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import { AuthProvider } from "./provider.tsx";
import { AuthConfig } from "./auth.ts";

const authConfig = new AuthConfig({
  authorize(user) {
    console.log("authorize", user);

    return new Promise((r) => r({ accessToken: "access token", refreshToken: "refresh token" }));
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <AuthProvider authConfig={authConfig}>
    <App />
  </AuthProvider>
);
