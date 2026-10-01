import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: [
    "127.0.0.1",
    "localhost",
    "10.162.93.201",
    // Freebuff preview tunnel (the origin the phone actually opens).
    // Without this, Next dev answers 403 to crossorigin chunk requests
    // from the tunnel, the page component never loads, and every
    // button/nav control is dead in the browser.
    "3000-itfjd1alfkz2kpnvwezw0.e2b.app",
    "*.e2b.app",
  ],
  async rewrites() {
    return [
      {
        source: "/scan",
        destination: "http://127.0.0.1:8000/scan",
      },
      {
        source: "/secure",
        destination: "http://127.0.0.1:8000/secure",
      },
      {
        source: "/status",
        destination: "http://127.0.0.1:8000/status",
      },
      {
        source: "/agent/:path*",
        destination: "http://127.0.0.1:8000/agent/:path*",
      },
      {
        // Security Agent Workforce — real Hacker backend.
        // Same-origin rewrite so the UI reads the persisted
        // canonical findings and Developer handoff state.
        source: "/workforce/:path*",
        destination: "http://127.0.0.1:8000/workforce/:path*",
      },
      {
        source: "/reset",
        destination: "http://127.0.0.1:8000/reset",
      },
    ];
  },
};

export default nextConfig;
