import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: [
    "127.0.0.1",
    "localhost",
    "10.162.93.201",
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
    ];
  },
};

export default nextConfig;
