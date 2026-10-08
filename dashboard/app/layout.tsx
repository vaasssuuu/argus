import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Argus: prove it, don't guess",
  description:
    "Is your app one guessed ID away from a breach? Argus is an autonomous agent that finds IDOR / broken access control and proves each finding with a real exploit in an isolated sandbox.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
