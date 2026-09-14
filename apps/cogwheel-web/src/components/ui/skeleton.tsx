"use client";

import { ark } from "@ark-ui/react/factory";
import { cn } from "@/lib/utils";

export const Skeleton = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn(
        "rounded-md bg-muted",
        "animate-pulse",
        "motion-reduce:animate-none!",
        className
      )}
      data-slot="skeleton"
      {...rest}
    />
  );
};
