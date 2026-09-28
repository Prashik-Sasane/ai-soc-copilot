'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import Navigation from '@/components/Navigation';

const PUBLIC_PATHS = ['/login', '/register'];

export default function LayoutContent({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.includes(pathname);

  if (isPublic) {
    return <>{children}</>;
  }

  return (
    <>
      <Navigation />
      <main className="pt-20 pl-[270px] pr-6 pb-12 transition-all">
        <div className="max-w-[1600px] mx-auto space-y-6">
          {children}
        </div>
      </main>
    </>
  );
}
