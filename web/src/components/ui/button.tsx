import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import type { ButtonHTMLAttributes } from "react"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg border text-sm font-medium transition-[transform,background-color,border-color,color] duration-160 ease-out motion-safe:active:scale-[0.97] disabled:pointer-events-none disabled:border-rule-2 disabled:bg-hover disabled:text-disabled aria-disabled:border-rule-2 aria-disabled:bg-hover aria-disabled:text-disabled [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "border-ink bg-ink text-bg hover:border-ink-2 hover:bg-ink-2",
        outline: "border-rule-2 bg-bg text-ink hover:bg-hover",
        ghost: "border-transparent text-ink-2 hover:bg-hover hover:text-ink",
        // A lone Cancel or Stop: it must read as a button beside no other.
        tinted: "border-rule-2 bg-hover text-ink hover:bg-sel",
      },
      size: {
        page: "h-10 px-4",
        default: "h-9 px-3.5",
        sm: "h-8 px-2.5 text-[13px]",
        icon: "size-8",
        // Today's name for the page size, until its callers move to it.
        lg: "h-10 px-4",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
)

interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

function Button({ className, variant, size, asChild = false, ...props }: ButtonProps) {
  const Comp = asChild ? Slot : "button"
  return <Comp className={cn(buttonVariants({ variant, size, className }))} {...props} />
}

export { Button, buttonVariants }
