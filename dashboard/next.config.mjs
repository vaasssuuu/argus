/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export — the dashboard is a pure replay of committed trace JSON, no backend.
  output: "export",
  images: { unoptimized: true },
};

export default nextConfig;
