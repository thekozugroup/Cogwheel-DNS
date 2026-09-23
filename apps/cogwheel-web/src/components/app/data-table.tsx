import React from "react";
import { cn } from "@/lib/utils";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState, LoadingSkeleton } from "@/components/app/states";

/** Container widths a table may shed a column or restack at, in pixels. */
type ColumnBreakpoint = "sm" | "md" | "lg" | "xl" | "2xl" | "3xl" | "4xl";

/** The same widths Tailwind's `@sm`–`@4xl` container queries use. */
const WIDTH: Record<ColumnBreakpoint, number> = {
  sm: 384,
  md: 448,
  lg: 512,
  xl: 576,
  "2xl": 672,
  "3xl": 768,
  "4xl": 896,
};

export type Column<Row> = {
  key: string;
  header: string;
  align?: "start" | "end";
  /**
   * Rendered in the stacked card's own header strip instead of as a
   * label/value pair. For a column whose cell is a control rather than a value:
   * a row menu or a pair of icon buttons has no label worth printing, and
   * dropping it instead would take the row's actions away from exactly the
   * people on the narrowest screens.
   */
  stackHeader?: boolean;
  /**
   * Let this cell wrap instead of truncating. For the columns that carry a
   * sentence rather than a value — a list's error or its protected-names note —
   * an ellipsis hides the only thing the column is there to say, and there is
   * no tooltip on a phone.
   */
  wrap?: boolean;
  /**
   * Container width below which this column is dropped from the table form.
   * Measured against the table's own container rather than the viewport: these
   * tables sit in side-by-side layouts, so a wider window can mean a *narrower*
   * table, and a viewport query would shed columns exactly backwards.
   */
  hideBelow?: ColumnBreakpoint;
  className?: string;
  headClassName?: string;
  render: (row: Row) => React.ReactNode;
};

export type DataTableProps<Row> = {
  columns: Column<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  empty: { icon: React.ElementType; title: string; description: string; action?: React.ReactNode };
  onRowClick?: (row: Row) => void;
  /** Accessible label describing what the row click does. */
  rowActionLabel?: (row: Row) => string;
  caption?: string;
  /**
   * Container width below which the rows render as stacked cards instead of a
   * table. Defaults to `sm`, which is where a two-or-three column table stops
   * fitting. Wide tables should raise it rather than let themselves be crushed.
   */
  stackBelow?: ColumnBreakpoint;
  /**
   * A purpose-built narrow row, used in place of the generic label/value card.
   * The generic form prints every column as its own line, which is right for a
   * ten-row table of settings and catastrophic for a two-hundred-row log: see
   * Activity, where five labelled lines per row made the page 40,000px tall.
   */
  card?: (row: Row) => React.ReactNode;
  /**
   * Cap the table body's height and pin the header to the top of it. For long
   * logs, so the column headings and whatever sits below the table stay on
   * screen instead of scrolling away in the first screenful.
   */
  stickyHeader?: boolean;
  className?: string;
};

/**
 * Measures the table's own container and reports which breakpoints it clears.
 *
 * Every width decision here used to be a CSS container query, which meant both
 * the table and the stacked cards were in the DOM at all times with one hidden.
 * On Activity that was 400 row renders and 400 duplicate `aria-label`s for 200
 * rows. Observing the width instead renders exactly one of the two.
 *
 * Null until the first measurement: `useLayoutEffect` takes it before the
 * browser paints, so nothing flashes, and the initial `null` renders the table
 * form rather than nothing so the very first frame is never blank.
 */
function useContainerWidth(): [React.RefObject<HTMLDivElement | null>, number | null] {
  const ref = React.useRef<HTMLDivElement>(null);
  const [width, setWidth] = React.useState<number | null>(null);

  React.useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;

    setWidth(element.clientWidth);
    if (typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver((entries) => {
      const measured = entries[0]?.contentRect.width;
      // Rounded: a fractional resize on every scrollbar appearance would
      // re-render every row of a 200-row log for a third of a pixel.
      if (measured !== undefined) setWidth(Math.round(measured));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return [ref, width];
}

/**
 * One table implementation for the whole app so loading, empty, error and
 * populated states are impossible to forget. When the container is too narrow
 * for the table, the same rows render as stacked cards instead — the brief
 * forbids horizontal body scroll at 375px, and a six-column table cannot honour
 * that any other way.
 */
export function DataTable<Row>({
  columns,
  rows,
  rowKey,
  loading = false,
  error = null,
  onRetry,
  empty,
  onRowClick,
  rowActionLabel,
  caption,
  stackBelow = "sm",
  card,
  stickyHeader = false,
  className,
}: DataTableProps<Row>) {
  const [ref, width] = useContainerWidth();

  // The measuring div has to be mounted for the measurement to happen, so the
  // empty, error and loading states render inside it rather than instead of it.
  let body: React.ReactNode;

  if (loading && rows.length === 0) {
    body = <LoadingSkeleton rows={4} variant="table" />;
  } else if (error && rows.length === 0) {
    body = <ErrorState detail={error} onRetry={onRetry} title="Could not load this list" />;
  } else if (rows.length === 0) {
    body = (
      <EmptyState
        action={empty.action}
        description={empty.description}
        icon={empty.icon}
        title={empty.title}
      />
    );
  } else {
    const stacked = width !== null && width < WIDTH[stackBelow];
    body = stacked
      ? renderStacked({ columns, rows, rowKey, onRowClick, rowActionLabel, card })
      : renderTable({
          columns: columns.filter(
            (column) => !column.hideBelow || width === null || width >= WIDTH[column.hideBelow],
          ),
          rows,
          rowKey,
          onRowClick,
          rowActionLabel,
          caption,
          stickyHeader,
        });
  }

  return (
    <div className={cn("min-w-0", className)} ref={ref}>
      {error && rows.length > 0 ? (
        <p className="mb-3 text-muted-foreground text-sm">
          Showing last-known rows. Latest refresh failed: {error}
        </p>
      ) : null}
      {body}
    </div>
  );
}

function renderTable<Row>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowActionLabel,
  caption,
  stickyHeader,
}: {
  columns: Column<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  onRowClick?: (row: Row) => void;
  rowActionLabel?: (row: Row) => string;
  caption?: string;
  stickyHeader: boolean;
}) {
  const interactive = Boolean(onRowClick);

  return (
    <div className={cn("overflow-x-auto", stickyHeader && "max-h-[50vh] overflow-y-auto")}>
      <Table>
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead
                className={cn(
                  "text-xs",
                  column.align === "end" && "text-right",
                  // The header has to carry its own background, or the rows
                  // scroll underneath a transparent strip.
                  stickyHeader && "sticky top-0 z-10 bg-card",
                  column.headClassName,
                )}
                key={column.key}
              >
                {column.header}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow
              className={cn(interactive && "cursor-pointer")}
              key={rowKey(row)}
              onClick={interactive ? () => onRowClick?.(row) : undefined}
              onKeyDown={
                interactive
                  ? (event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onRowClick?.(row);
                      }
                    }
                  : undefined
              }
              {...(interactive
                ? { tabIndex: 0, role: "button", "aria-label": rowActionLabel?.(row) }
                : {})}
            >
              {columns.map((column) => (
                <TableCell
                  className={cn(
                    column.wrap ? "max-w-[26rem] whitespace-normal" : "max-w-[22rem] truncate",
                    column.align === "end" && "text-right",
                    column.className,
                  )}
                  key={column.key}
                >
                  {column.render(row)}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function renderStacked<Row>({
  columns,
  rows,
  rowKey,
  onRowClick,
  rowActionLabel,
  card,
}: {
  columns: Column<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  onRowClick?: (row: Row) => void;
  rowActionLabel?: (row: Row) => string;
  card?: (row: Row) => React.ReactNode;
}) {
  if (card) {
    return (
      <ul className="divide-y divide-border">
        {rows.map((row) => (
          <li key={rowKey(row)}>{card(row)}</li>
        ))}
      </ul>
    );
  }

  const interactive = Boolean(onRowClick);
  const headerColumns = columns.filter((column) => column.stackHeader);
  const valueColumns = columns.filter((column) => !column.stackHeader);

  return (
    <ul className="flex flex-col gap-2">
      {rows.map((row) => {
        // A column that renders nothing for this row would print a label with
        // an empty space beside it. In the table form the header carries the
        // column; in a card there is nothing left to explain the gap.
        const cells = valueColumns
          .map((column) => ({ column, value: column.render(row) }))
          .filter(({ value }) => value !== null && value !== undefined && value !== false && value !== "");

        const body = (
          <dl className="grid gap-2">
            {cells.map(({ column, value }) =>
              // A `wrap` column carries a sentence rather than a value — a
              // list's download error, its advisory note. A sentence set ragged
              // -left against the right edge of a 327px card is hard to read
              // and looks like a mistake, so it gets the full width with its
              // label above it instead of sharing a line with it.
              column.wrap ? (
                <div className="grid gap-1" key={column.key}>
                  <dt className="text-muted-foreground text-xs">{column.header}</dt>
                  <dd className="stacked-value min-w-0 text-foreground text-sm">{value}</dd>
                </div>
              ) : (
                <div className="flex items-start justify-between gap-3" key={column.key}>
                  <dt className="shrink-0 text-muted-foreground text-xs">{column.header}</dt>
                  <dd className="stacked-value min-w-0 text-right text-foreground text-sm">{value}</dd>
                </div>
              ),
            )}
          </dl>
        );

        return (
          <li key={rowKey(row)}>
            <div className="flex flex-col gap-2 rounded-xl border border-border p-3">
              {headerColumns.length > 0 ? (
                <div className="flex items-center justify-end gap-1">
                  {headerColumns.map((column) => (
                    <React.Fragment key={column.key}>{column.render(row)}</React.Fragment>
                  ))}
                </div>
              ) : null}
              {interactive ? (
                <button
                  aria-label={rowActionLabel?.(row)}
                  className="-m-1 rounded-lg p-1 text-left hover:bg-muted/50"
                  onClick={() => onRowClick?.(row)}
                  type="button"
                >
                  {body}
                </button>
              ) : (
                body
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
