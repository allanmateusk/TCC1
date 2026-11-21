export function transport(fetcher, token) {
  if (typeof token !== "string" || !token || /[\r\n]/.test(token)) throw new Error("MISSING_OR_INVALID_SECRET");
  return async (url, method) => {
    if (!/^https:\/\/api\.runpod\.io\/v2\/(account|pods\/[A-Za-z0-9_-]+(\/action)?)$/.test(url)
        || (method === "POST") !== url.endsWith("/action") || !["GET", "POST"].includes(method)) throw new Error("UNEXPECTED_REQUEST");
    const options = { method, redirect: "error", cache: "no-store", signal: AbortSignal.timeout(4_000),
      headers: { Authorization: "Bearer " + token } };
    if (method === "POST") {
      options.headers["Content-Type"] = "application/json";
      options.body = '{"action":"stop"}';
    }
    const response = await fetcher(url, options);
    if (method === "POST" || response.status !== 200) {
      await response.body?.cancel();
      return { status: response.status };
    }
    return { status: response.status, data: await response.json() };
  };
}
