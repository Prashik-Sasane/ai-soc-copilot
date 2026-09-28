import type { Metadata } from 'next';
import './globals.css';
import AuthGuard from '@/components/AuthGuard';
import LayoutContent from '@/components/LayoutContent';

export const metadata: Metadata = {
  title: 'AI SOC Copilot - Security Operations Center',
  description: 'Evidence-grounded SOC Copilot for automated triage, correlation, threat intelligence, and RAG investigation.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-soc-bg text-soc-textMain antialiased min-h-screen">
        <AuthGuard>
          <LayoutContent>{children}</LayoutContent>
        </AuthGuard>
      </body>
    </html>
  );
}
