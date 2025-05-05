import * as React from 'react';
import { Avatar, AvatarFallback } from './avatar';

interface AvatarGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  limit?: number;
}

export function AvatarGroup({ limit = 3, className, children, ...props }: AvatarGroupProps) {
  const childrenArray = React.Children.toArray(children);
  const visibleAvatars = limit ? childrenArray.slice(0, limit) : childrenArray;
  const remainingAvatars = limit ? Math.max(0, childrenArray.length - limit) : 0;

  return (
    <div className="flex -space-x-2" {...props}>
      {visibleAvatars}
      {remainingAvatars > 0 && (
        <Avatar className="h-8 w-8 bg-muted text-muted-foreground border-2 border-background">
          <AvatarFallback>+{remainingAvatars}</AvatarFallback>
        </Avatar>
      )}
    </div>
  );
}

