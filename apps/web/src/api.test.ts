import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("sends JSON requests to the configured local API", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(api<{ status: string }>("/healthz", { method: "POST" })).resolves.toEqual({ status: "ok" });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:4700/healthz",
      expect.objectContaining({ method: "POST", headers: { "content-type": "application/json" } })
    );
  });

  it("surfaces the bounded API error detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "DNS ownership verification has not been completed." }), {
          status: 409,
          headers: { "content-type": "application/json" }
        })
      )
    );

    await expect(api("/api/engagements/example/assessments")).rejects.toThrow(
      "DNS ownership verification has not been completed."
    );
  });
});
