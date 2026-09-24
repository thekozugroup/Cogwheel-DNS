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
   * The cell that names the row: a device's name, a list's name. When the
   * table has `onRowClick`, this cell's content is rendered inside a real
   * <button> — the row's one tab stop and its accessible action — and the
   * other cells stay ordinary cells a screen reader reads with their column
   * headers. Defaults to the first column.
   */
  primary?: boolean;
  /**
   * Keep the header for assistive technology but draw nothing. An empty
   * `header` gets this automatically, labelled "Actions": a <th> with no text
   * is a column nobody can navigate to by name.
   */
  hideHeader?: boolean;
  /**
   * Rendered at the trailing edge of the stacked row instead of as a
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
  /**
   * What failed to load, as a sentence: "Could not load your lists". The
   * generic "Could not load this list" read as one blocklist on Lists and as
   * nothing in particular everywhere else.
   */
  errorTitle?: string;
  /**
   * Opens the row. The primary cell becomes a <button> that does this, and a
   * click anywhere else on the row does it too, as a mouse convenience — the
   * row itself is never the control.
   */
  onRowClick?: (row: Row) => void;
  /**
   * The primary button's accessible name, e.g. "Edit Work Laptop". It should
   * contain the visible text (WCAG 2.5.3); it names the button only, so the
   * rest of the row is still read as the row's cells.
   */
  rowActionLabel?: (row: Row) => string;
  caption?: string;
  /**
   * Container width below which the rows render as stacked cards instead of a
   * table. Defaults to `sm`, which is where a two-or-three column table stops
   * fitting. Wide tables should raise it rather than let themselves be crushed.
   */
  stackBelow?: ColumnBreakpoint;
  /**
   * A purpose-built narrow row, used in place of the generic stacked row.
   * Return a <NarrowRow> (exported below). The generic form prints every
   * column as its own line, which is right for a ten-row table of settings and
   * catastrophic for a two-hundred-row log: see Activity, where five labelled
   * lines per row made the page 40,000px tall.
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
  errorTitle = "Could not load these rows",
  onRowClick,
  rowActionLabel,
  caption,
  stackBelow = "sm",
  card,
  stickyHeader = false,
  className,
}: DataTableProps<Row>) {
  const [ref, width] = useContainerWidth();
  // The same array while the width stays on the same side of every
  // breakpoint, so memoised rows are not re-rendered by a new column list.
  const shownKey = columns
    .map((column) => (!column.hideBelow || width === null || width >= WIDTH[column.hideBelow] ? "1" : "0"))
    .join("");
  const shownColumns = React.useMemo(
    () => columns.filter((_, index) => shownKey[index] === "1"),
    [columns, shownKey],
  );

  // The measuring div has to be mounted for the measurement to happen, so the
  // empty, error and loading states render inside it rather than instead of it.
  let body: React.ReactNode;

  if (loading && rows.length === 0) {
    body = <LoadingSkeleton rows={4} variant="table" />;
  } else if (error && rows.length === 0) {
    body = <ErrorState detail={error} onRetry={onRetry} title={errorTitle} />;
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
          columns: shownColumns,
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

/**
 * Whether a click on a row should open it. Clicks that land on a control inside
 * the row belong to that control, and a click that ends a text selection is
 * someone copying an address. Portaled content — a row menu's items, a dialog
 * a cell opened — bubbles through React to the row without being inside it in
 * the DOM, and is not the row's either.
 */
const CONTROL =
  'a, button, input, select, textarea, label, summary, [role="button"], [role="switch"], [role="menuitem"], [role="option"]';

function isRowOpenClick(event: React.MouseEvent<HTMLElement>): boolean {
  const target = event.target as Element | null;
  if (!target || !event.currentTarget.contains(target)) return false;
  if (target.closest(CONTROL)) return false;
  const selection = window.getSelection();
  if (selection && !selection.isCollapsed && selection.toString().trim() !== "") return false;
  return true;
}

function primaryOf<Row>(columns: Column<Row>[]): Column<Row> | undefined {
  return columns.find((column) => column.primary) ?? columns.find((column) => !column.stackHeader);
}

function HeaderText({ column }: { column: { header: string; hideHeader?: boolean } }) {
  const text = column.header.trim() === "" ? "Actions" : column.header;
  return column.hideHeader || column.header.trim() === "" ? <span className="sr-only">{text}</span> : <>{text}</>;
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
  const primary = onRowClick ? primaryOf(columns) : undefined;

  return (
    <Table wrapperClassName={cn(stickyHeader && "max-h-[50vh]")}>
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
              <HeaderText column={column} />
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <DataRow
            columns={columns}
            key={rowKey(row)}
            onRowClick={onRowClick}
            primary={primary}
            row={row}
            rowActionLabel={rowActionLabel}
          />
        ))}
      </TableBody>
    </Table>
  );
}

type DataRowProps<Row> = {
  row: Row;
  columns: Column<Row>[];
  primary?: Column<Row>;
  onRowClick?: (row: Row) => void;
  rowActionLabel?: (row: Row) => string;
};

function DataRowBody<Row>({ row, columns, primary, onRowClick, rowActionLabel }: DataRowProps<Row>) {
  return (
    <TableRow
      className={cn(primary && "cursor-pointer")}
      onClick={
        primary
          ? (event) => {
              if (isRowOpenClick(event)) onRowClick?.(row);
            }
          : undefined
      }
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
          {column === primary ? (
            <RowButton label={rowActionLabel?.(row)} onClick={() => onRowClick?.(row)} wrap={column.wrap}>
              {column.render(row)}
            </RowButton>
          ) : (
            column.render(row)
          )}
        </TableCell>
      ))}
    </TableRow>
  );
}

/**
 * One row, re-rendered only when its record or the columns change. A batch of
 * live rows on Activity used to render every TableRow and TableCell of all
 * fifty — about a thousand components a commit — although each cell under
 * them bailed out; now a batch renders the rows it adds.
 */
const DataRow = React.memo(DataRowBody) as typeof DataRowBody;

/**
 * The primary cell's button. It fills its cell, padding included, so the focus
 * ring can be drawn inside it: the cell truncates (overflow hidden) and the
 * table wrapper scrolls, and an outline drawn outside either was clipped to a
 * sliver — the audit measured it. Inset, it outlines the cell exactly.
 */
function RowButton({
  label,
  onClick,
  wrap,
  children,
}: {
  label?: string;
  onClick: () => void;
  wrap?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      aria-label={label}
      className={cn(
        "-mx-2 -my-2 block w-[calc(100%+1rem)] rounded-md px-2 py-2 text-left",
        "font-medium text-foreground underline-offset-4 hover:underline",
        "focus-visible:-outline-offset-2",
        wrap ? "whitespace-normal" : "truncate",
      )}
      data-slot="row-button"
      onClick={onClick}
      type="button"
    >
      {children}
    </button>
  );
}

/**
 * The generic narrow form: one divided row per record, no border of its own.
 * It used to be a bordered, rounded card per row inside the bordered section
 * card — a border around a border, which DESIGN.md §5 rules out. The primary
 * value is the row's first line (a button when the table opens rows), the
 * other columns follow as label/value pairs, and control columns sit at the
 * trailing edge of the first line.
 */
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
  const controlColumns = columns.filter((column) => column.stackHeader);
  const primary = primaryOf(columns);
  const valueColumns = columns.filter((column) => !column.stackHeader && column !== primary);

  return (
    <ul className="divide-y divide-border">
      {rows.map((row) => {
        // A column that renders nothing for this row would print a label with
        // an empty space beside it. In the table form the header carries the
        // column; in a stacked row there is nothing left to explain the gap.
        const cells = valueColumns
          .map((column) => ({ column, value: column.render(row) }))
          .filter(({ value }) => value !== null && value !== undefined && value !== false && value !== "");

        return (
          <li
            className={cn("flex items-start gap-3 py-3", interactive && "cursor-pointer")}
            key={rowKey(row)}
            onClick={
              interactive
                ? (event) => {
                    if (isRowOpenClick(event)) onRowClick?.(row);
                  }
                : undefined
            }
          >
            <div className="min-w-0 flex-1">
              {primary ? (
                <div className="stacked-value min-w-0 text-foreground text-sm">
                  {interactive ? (
                    <button
                      aria-label={rowActionLabel?.(row)}
                      className="max-w-full rounded-sm text-left font-medium underline-offset-4 hover:underline"
                      onClick={() => onRowClick?.(row)}
                      type="button"
                    >
                      {primary.render(row)}
                    </button>
                  ) : (
                    primary.render(row)
                  )}
                </div>
              ) : null}
              {cells.length > 0 ? (
                <dl className={cn("grid gap-1.5", primary && "mt-2")}>
                  {cells.map(({ column, value }) =>
                    // A `wrap` column carries a sentence rather than a value — a
                    // list's download error, its advisory note. Set ragged-left
                    // against the right edge of a phone it is hard to read and
                    // looks like a mistake, so it gets the full width with its
                    // label above it instead of sharing a line with it.
                    column.wrap ? (
                      <div className="grid gap-0.5" key={column.key}>
                        <dt className="text-muted-foreground text-xs">{column.header}</dt>
                        <dd className="stacked-value min-w-0 text-foreground text-sm">{value}</dd>
                      </div>
                    ) : (
                      <div className="flex items-baseline justify-between gap-3" key={column.key}>
                        <dt className="shrink-0 text-muted-foreground text-xs">{column.header}</dt>
                        <dd className="stacked-value min-w-0 text-right text-foreground text-sm">{value}</dd>
                      </div>
                    ),
                  )}
                </dl>
              ) : null}
            </div>
            {controlColumns.length > 0 ? (
              <div className="-my-1 flex shrink-0 items-center gap-1">
                {controlColumns.map((column) => (
                  <React.Fragment key={column.key}>{column.render(row)}</React.Fragment>
                ))}
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The purpose-built narrow row DESIGN.md §5 asks for: the identifying values
 * on the first line and the ones you came to read on the second (and a third
 * where they will not share one), separated by the list's own divider. Return it from DataTable's
 * `card` prop.
 *
 *   ● ads.tiktok.com                      6:12:36 PM   [⋯]
 *   Blocked · household rule · Sam's iPhone
 *
 * With `onOpen`, the title is a real <button> named by `openLabel` — the row's
 * one tab stop — and a click anywhere else on the row opens it too. Without
 * it the title is text and the row is read, not opened.
 */
export function NarrowRow({
  title,
  titleClassName,
  lead,
  meta,
  metaClassName,
  detail,
  actions,
  onOpen,
  openLabel,
  className,
}: {
  /** The identifying value: a device name, a domain. Truncates. */
  title: React.ReactNode;
  /** e.g. `font-mono` for a domain. */
  titleClassName?: string;
  /** A leading status dot on the first line. */
  lead?: React.ReactNode;
  /** The first line's trailing value: a time, an address. Never truncates. */
  meta?: React.ReactNode;
  metaClassName?: string;
  /** The second line: state and counts, in words. */
  detail?: React.ReactNode;
  /** Trailing controls, e.g. a RowMenu. */
  actions?: React.ReactNode;
  /** Makes the title a button, and the row clickable, that does this. */
  onOpen?: () => void;
  /** The title button's accessible name; should contain the visible title. */
  openLabel?: string;
  className?: string;
}) {
  return (
    <div
      className={cn("flex items-start gap-3 py-3", onOpen && "cursor-pointer", className)}
      onClick={
        onOpen
          ? (event) => {
              if (isRowOpenClick(event)) onOpen();
            }
          : undefined
      }
    >
      <div className="min-w-0 flex-1">
        <p className="flex items-baseline gap-2">
          {lead ? <span className="flex shrink-0 self-center">{lead}</span> : null}
          {onOpen ? (
            <button
              aria-label={openLabel}
              className={cn(
                "min-w-0 flex-1 truncate rounded-sm text-left font-medium text-foreground text-sm",
                "underline-offset-4 hover:underline",
                titleClassName,
              )}
              onClick={onOpen}
              type="button"
            >
              {title}
            </button>
          ) : (
            <span className={cn("min-w-0 flex-1 truncate text-foreground text-sm", titleClassName)}>{title}</span>
          )}
          {meta ? (
            <span className={cn("tabular shrink-0 text-muted-foreground text-xs", metaClassName)}>{meta}</span>
          ) : null}
        </p>
        {detail ? <div className="mt-1 min-w-0 text-muted-foreground text-xs">{detail}</div> : null}
      </div>
      {actions ? <div className="-my-1 flex shrink-0 items-center gap-1">{actions}</div> : null}
    </div>
  );
}
