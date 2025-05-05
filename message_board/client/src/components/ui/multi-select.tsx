import * as React from 'react';
import { X } from 'lucide-react';

import { cn } from '@/lib/utils';
import { MultiSelect as MultiSelectPrimitive } from '@/components/primitives/multi-select';

const MultiSelect = MultiSelectPrimitive;

const MultiSelectTrigger = React.forwardRef<
  React.ElementRef<typeof MultiSelectPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof MultiSelectPrimitive.Trigger>
>(({ className, children, ...props }, ref) => (
  <MultiSelectPrimitive.Trigger
    ref={ref}
    className={cn(
      'flex w-full items-center justify-start rounded-md border border-input bg-popover px-3 py-2 text-sm text-popover-foreground ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 rounded-md ',

      className,
    )}
    {...props}
  >
    {children}
  </MultiSelectPrimitive.Trigger>
));

const MultiSelectValue = React.forwardRef<
  React.ElementRef<typeof MultiSelectPrimitive.Value>,
  React.ComponentPropsWithoutRef<typeof MultiSelectPrimitive.Value>
>(({ className, ...props }, ref) => (
  <MultiSelectPrimitive.Value
    ref={ref}
    className={cn('line-clamp-1 flex-1 text-left text-muted-foreground rounded-md', className)}
    style={{
      justifyContent: 'flex-start',
    }}
    {...props}
  />
));
MultiSelectValue.displayName = MultiSelectPrimitive.Value.displayName;

const MultiSelectContent = React.forwardRef<
  React.ElementRef<typeof MultiSelectPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof MultiSelectPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <MultiSelectPrimitive.Content
    ref={ref}
    className={cn(
      'relative z-50 max-h-96 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 data-[side=bottom]:translate-y-1',
      className,
    )}
    {...props}
  >
    {children}
  </MultiSelectPrimitive.Content>
));
MultiSelectContent.displayName = MultiSelectPrimitive.Content.displayName;

const MultiSelectItem = React.forwardRef<
  React.ElementRef<typeof MultiSelectPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof MultiSelectPrimitive.Item>
>(({ className, children, ...props }, ref) => (
  <MultiSelectPrimitive.Item
    ref={ref}
    className={cn(
      'relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50 hover:bg-accent',
      className,
    )}
    {...props}
  >
    <span className="flex-1">{children}</span>
  </MultiSelectPrimitive.Item>
));
MultiSelectItem.displayName = MultiSelectPrimitive.Item.displayName;

const MultiSelectTag = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<'div'> & { value: string; onRemove: () => void }
>(({ className, children, onRemove, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      'flex items-center gap-1 rounded-sm bg-secondary px-1 py-0.5 text-xs text-secondary-foreground',
      className,
    )}
    {...props}
  >
    <span>{children}</span>
    <button
      className="flex h-3.5 w-3.5 items-center justify-center rounded-sm hover:bg-secondary-foreground/20"
      onClick={onRemove}
      type="button"
      aria-label="Remove"
    >
      <X className="h-3 w-3" />
    </button>
  </div>
));
MultiSelectTag.displayName = 'MultiSelectTag';

// Custom separator similar to SelectSeparator
const MultiSelectSeparator = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('-mx-1 my-1 h-px bg-muted', className)} {...props} />
  ),
);
MultiSelectSeparator.displayName = 'MultiSelectSeparator';

export {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
  MultiSelectTag,
  MultiSelectSeparator,
};
