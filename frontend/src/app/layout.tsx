import type { Metadata } from 'next';
import './globals.css';
import Navigation from '@/components/Navigation';

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
        <Navigation />
        <main className="pt-20 pl-[270px] pr-6 pb-12 transition-all">
          <div className="max-w-[1600px] mx-auto space-y-6">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
