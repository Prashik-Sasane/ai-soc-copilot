import React from 'react';

interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
}

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const sev = severity.toLowerCase();
  
  if (sev === 'critical') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider badge-critical">
        CRITICAL
      </span>
    );
  } else if (sev === 'high') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider badge-high">
        HIGH
      </span>
    );
  } else if (sev === 'medium') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider badge-medium">
        MEDIUM
      </span>
    );
  } else {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider badge-low">
        LOW
      </span>
    );
  }
}
