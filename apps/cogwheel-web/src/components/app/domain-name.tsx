import React from "react";

/**
 * A domain with a line-break opportunity before each dot, so a name too long
 * for its row breaks as "googlesyndication" / ".com" rather than mid-label,
 * and does not truncate: a rule list at 375px cut "app-measurement.com" to
 * "app-measurement…", which is the one part of the row that identifies it.
 * The arbitrary break is left for a single label longer than the row — give
 * the parent `[overflow-wrap:anywhere]`.
 */
export function DomainName({ name }: { name: string }) {
  const [head, ...labels] = name.split(".");
  return (
    <>
      {head}
      {labels.map((label, index) => (
        // Labels repeat ("a.b.a"), so position is the only stable key.
        <React.Fragment key={index}>
          <wbr />.{label}
        </React.Fragment>
      ))}
    </>
  );
}
