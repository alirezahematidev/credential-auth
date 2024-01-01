import { useAuthConfig, useAuthCredential } from "./provider";

function App() {
  const { signIn, setUser } = useAuthConfig();

  const { payload } = useAuthCredential();

  console.log({ payload });

  return (
    <div>
      <button onClick={() => signIn({ sub: "alireza123" })}>sign in</button>
      <button onClick={() => setUser({ accessToken: "aaa", refreshToken: "bbb" })}>set user</button>
    </div>
  );
}

export default App;
