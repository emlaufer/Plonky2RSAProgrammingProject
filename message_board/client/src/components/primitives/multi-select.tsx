import * as React from 'react';
import * as Popover from '@radix-ui/react-popover';
import { createContext, useContext, useState, useEffect } from 'react';
import { Check, ChevronDown, ChevronUp, X } from 'lucide-react';
import { cn } from '@/lib/utils';

// Define a type for selected items to track both value and content
type SelectedItem = {
  value: string;
  content: React.ReactNode;
};

// Context for the MultiSelect
const MultiSelectContext = createContext<{
  selectedItems: SelectedItem[];
  selectedValues: string[];
  addItem: (item: SelectedItem) => void;
  removeItem: (value: string) => void;
  isSelected: (value: string) => boolean;
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
}>({
  selectedItems: [],
  selectedValues: [],
  addItem: () => {},
  removeItem: () => {},
  isSelected: () => false,
  open: false,
  setOpen: () => {},
});

// Root component
const MultiSelectRoot = React.forwardRef<
  HTMLDivElement,
  {
    children: React.ReactNode;
    defaultValues?: string[];
    value?: string[];
    onValueChange?: (value: string[]) => void;
    defaultOpen?: boolean;
    open?: boolean;
    onOpenChange?: (open: boolean) => void;
  }
>(
  (
    {
      children,
      defaultValues = [],
      value,
      onValueChange,
      defaultOpen = false,
      open: controlledOpen,
      onOpenChange,
      ...props
    },
    forwardedRef,
  ) => {
    // Store both value and content for each selected item
    const [selectedItems, setSelectedItems] = useState<SelectedItem[]>([]);
    const [uncontrolledOpen, setUncontrolledOpen] = useState(defaultOpen);

    const open = controlledOpen !== undefined ? controlledOpen : uncontrolledOpen;
    const setOpen = React.useCallback(
      (state: boolean | ((prev: boolean) => boolean)) => {
        if (onOpenChange) {
          if (typeof state === 'function') {
            onOpenChange(state(open));
          } else {
            onOpenChange(state);
          }
        } else {
          setUncontrolledOpen(state);
        }
      },
      [onOpenChange, open],
    );

    // Derived state for just the values
    const selectedValues = selectedItems.map((item) => item.value);

    // Add an item to selection
    const addItem = (item: SelectedItem) => {
      setSelectedItems((prev) => {
        // Check if it already exists
        if (prev.some((i) => i.value === item.value)) {
          return prev;
        }
        return [...prev, item];
      });
    };

    // Remove an item from selection
    const removeItem = (value: string) => {
      setSelectedItems((prev) => prev.filter((item) => item.value !== value));
    };

    // Check if a value is selected
    const isSelected = (value: string) => {
      return selectedItems.some((item) => item.value === value);
    };

    // Handle controlled component behavior for values
    useEffect(() => {
      if (value !== undefined) {
        // When external value changes, we need to reset our internal items
        // This will lose content display until items are re-selected or rendered
        setSelectedItems((prev) => {
          // Keep items that are still in the controlled value array
          const retained = prev.filter((item) => value.includes(item.value));

          // Find values that we don't have items for yet
          const missingValues = value.filter((v) => !retained.some((item) => item.value === v));

          // Create placeholder items for missing values (content will be updated when rendered)
          const placeholders = missingValues.map((v) => ({
            value: v,
            content: v, // Use value as fallback content
          }));

          return [...retained, ...placeholders];
        });
      }
    }, [value]);

    // Notify parent of value changes
    useEffect(() => {
      if (onValueChange) {
        onValueChange(selectedValues);
      }
    }, [selectedValues, onValueChange]);

    return (
      <MultiSelectContext.Provider
        value={{
          selectedItems,
          selectedValues,
          addItem,
          removeItem,
          isSelected,
          open,
          setOpen,
        }}
      >
        <Popover.Root open={open} onOpenChange={setOpen}>
          <div {...props} ref={forwardedRef} style={{ position: 'relative' }}>
            {children}
          </div>
        </Popover.Root>
      </MultiSelectContext.Provider>
    );
  },
);

MultiSelectRoot.displayName = 'MultiSelect';

// Trigger component
const MultiSelectTrigger = React.forwardRef<
  HTMLButtonElement,
  React.ComponentProps<typeof Popover.Trigger>
>(({ children, ...props }, forwardedRef) => {
  const { open } = useContext(MultiSelectContext);

  return (
    <Popover.Trigger {...props} ref={forwardedRef} asChild>
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-multiselectable="true"
        data-state={open ? 'open' : 'closed'}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'flex-start',
          width: '100%',
          padding: '8px 12px',
          cursor: 'pointer',
          ...props.style,
        }}
      >
        {children}
        {open ? (
          <ChevronUp className="opacity-50" size={16} />
        ) : (
          <ChevronDown className="opacity-50" size={16} />
        )}
      </button>
    </Popover.Trigger>
  );
});

MultiSelectTrigger.displayName = 'MultiSelect.Trigger';

// Value component
const MultiSelectValue = React.forwardRef<
  HTMLSpanElement,
  { placeholder?: string } & React.ComponentProps<'span'>
>(({ placeholder = 'Select items...', ...props }, forwardedRef) => {
  const { selectedItems } = useContext(MultiSelectContext);

  return (
    <span {...props} ref={forwardedRef} style={{ display: 'block', width: '100%', ...props.style }}>
      {selectedItems.length > 0 ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
          {selectedItems.map((item) => (
            <MultiSelectTag key={item.value} value={item.value}>
              {item.content}
            </MultiSelectTag>
          ))}
        </div>
      ) : (
        <span>{placeholder}</span>
      )}
    </span>
  );
});

MultiSelectValue.displayName = 'MultiSelect.Value';

// Tag component for selected values
const MultiSelectTag = React.forwardRef<
  HTMLDivElement,
  { value: string; children: React.ReactNode } & React.ComponentProps<'div'>
>(({ value, children, ...props }, forwardedRef) => {
  const { removeItem } = useContext(MultiSelectContext);

  const handleRemove = (e: React.MouseEvent) => {
    e.stopPropagation();
    removeItem(value);
  };

  return (
    <div
      {...props}
      ref={forwardedRef}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        borderRadius: '4px',
        padding: '2px 8px',
        fontSize: '14px',
        ...props.style,
      }}
    >
      <span>{children}</span>
      <button
        onClick={handleRemove}
        type="button"
        aria-label={`Remove ${value}`}
        style={{
          border: 'none',
          cursor: 'pointer',
          marginLeft: '4px',
          padding: '2px',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <X size={14} />
      </button>
    </div>
  );
});

MultiSelectTag.displayName = 'MultiSelect.Tag';

// Content component
const MultiSelectContent = React.forwardRef<
  HTMLDivElement,
  React.ComponentProps<typeof Popover.Content> & {
    searchPlaceholder?: string;
    onSearch?: (query: string, items: React.ReactElement[]) => React.ReactElement[];
    searchable?: boolean;
  }
>(
  (
    { children, searchPlaceholder = 'Search...', onSearch, searchable = true, ...props },
    forwardedRef,
  ) => {
    const [searchQuery, setSearchQuery] = useState('');

    // Convert children to array for filtering
    const childrenArray = React.Children.toArray(children) as React.ReactElement[];

    // Default filter implementation
    const defaultFilterFn = (query: string, items: React.ReactElement[]): React.ReactElement[] => {
      if (!query) return items;

      return items.filter((child) => {
        if (!React.isValidElement(child)) return true;

        // Extract text content from the child's props.children for searching
        const childContent = (child.props as any).children;
        if (!childContent) return true;

        // If children is a React element with props.children.props.children that contains text nodes
        // This is specifically for our current structure where Item > div > span contains user name
        let textToSearch = '';
        try {
          if (
            typeof childContent === 'object' &&
            childContent.props &&
            childContent.props.children
          ) {
            // Try to find text content in the nested structure
            React.Children.forEach(childContent.props.children, (nestedChild) => {
              if (React.isValidElement(nestedChild) && (nestedChild as any).props.children) {
                if (typeof (nestedChild as any).props.children === 'string') {
                  textToSearch += (nestedChild as any).props.children;
                }
              }
            });
          }
        } catch (e) {
          // Fail silently if structure doesn't match expectations
        }

        return textToSearch.toLowerCase().includes(query.toLowerCase());
      });
    };

    // Determine which filtering function to use
    const filteredChildren = onSearch
      ? onSearch(searchQuery, childrenArray)
      : defaultFilterFn(searchQuery, childrenArray);

    return (
      <Popover.Portal>
        <Popover.Content
          {...props}
          ref={forwardedRef}
          sideOffset={5}
          align="start"
          //avoidCollisions={false}
          className={cn(
            props.className,
            cn('bg-popover text-popover-foreground rounded-lg shadow-md'),
          )}
          style={{
            maxHeight: 'var(--radix-popover-content-available-height)',
            width: 'var(--radix-popover-trigger-width)',
            //transformOrigin: 'var(--radix-popover-content-transform-origin)',
          }}
        >
          {searchable && (
            <div className="sticky top-0 bg-popover border-b border-border p-2">
              <input
                type="text"
                placeholder={searchPlaceholder}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full p-2 border border-input  rounded-md bg-input text-foreground"
              />
            </div>
          )}
          <div
            className="overflow-y-auto"
            style={{
              maxHeight: 'var(--radix-popover-content-available-height)',
              paddingTop: searchable ? '8px' : '0', // Add padding to prevent overlap
            }}
          >
            {filteredChildren}
          </div>
        </Popover.Content>
      </Popover.Portal>
    );
  },
);

// Item component
const MultiSelectItem = React.forwardRef<
  HTMLDivElement,
  { value: string; children: React.ReactNode } & React.ComponentProps<'div'>
>(({ children, value, ...props }, forwardedRef) => {
  const { isSelected, addItem, removeItem } = useContext(MultiSelectContext);
  const selected = isSelected(value);

  const handleClick = () => {
    if (selected) {
      removeItem(value);
    } else {
      addItem({
        value,
        content: children,
      });
    }
  };

  return (
    <div
      {...props}
      ref={forwardedRef}
      role="option"
      aria-selected={selected}
      data-state={selected ? 'checked' : 'unchecked'}
      onClick={handleClick}
      style={{
        padding: '8px 12px',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        outline: 'none',
        userSelect: 'none',
        ...props.style,
      }}
    >
      {children}
      {selected && <Check size={16} />}
    </div>
  );
});

MultiSelectItem.displayName = 'MultiSelect.Item';

// Export the composed component
const MultiSelect = Object.assign(MultiSelectRoot, {
  Trigger: MultiSelectTrigger,
  Value: MultiSelectValue,
  Content: MultiSelectContent,
  Item: MultiSelectItem,
});
export { MultiSelect };
