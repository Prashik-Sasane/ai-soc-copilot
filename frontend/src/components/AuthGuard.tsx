'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { isAuthenticated, clearAuth, getCurrentUserProfile, UserItem } from '@/lib/api';

const PUBLIC_PATHS = ['/login', '/register'];

interface AuthGuardProps {
  children: React.ReactNode;
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const router = useRouter();
  const pathname = usePathname();
  const [isChecking, setIsChecking] = useState(true);
  const [user, setUser] = useState<UserItem | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      const isPublic = PUBLIC_PATHS.includes(pathname);
      const authed = isAuthenticated();

      if (isPublic) {
        if (authed) {
          router.replace('/');
          return;
        }
        setIsChecking(false);
        return;
      }

      if (!authed) {
        router.replace('/login');
        return;
      }

      try {
        const profile = await getCurrentUserProfile();
        setUser(profile);
        if (typeof window !== 'undefined') {
          localStorage.setItem('soc_user', JSON.stringify(profile));
        }
      } catch (e: any) {
        if (e.message && (e.message.includes('Session expired') || e.message.includes('Authentication required'))) {
          clearAuth();
          router.replace('/login');
          return;
        }
      }

      setIsChecking(false);
    };

    checkAuth();
  }, [pathname, router]);

  if (isChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-soc-bg">
        <div className="text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-cyan-glow mx-auto animate-pulse">
            <svg className="w-6 h-6 text-white animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014-10.659V14.29z" />
            </svg>
          </div>
          <p className="text-xs text-soc-textMuted font-mono">Authenticating session...</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

export function useAuthUser(): UserItem | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem('soc_user');
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserItem;
  } catch {
      return null;
    }
  }
