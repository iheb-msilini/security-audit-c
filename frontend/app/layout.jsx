import "./globals.css";

export const metadata = {
  title: "AuditSec Dashboard",
  description: "Cloud security audit control center",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
