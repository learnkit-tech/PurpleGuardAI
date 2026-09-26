import * as React from "react"

const MOBILE_BREAKPOINT = 768

export function useIsMobile() {
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined)

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`)
    const onChange = () => {
      setIsMobile(window.innerWidth < MOBILE_BREAKPOINT)
    }
    mql.addEventListener("change", onChange)
    // Initial value arrives in a task (not synchronously in the effect body)
    // to avoid a cascading render; the subscription covers later changes.
    const task = setTimeout(onChange, 0)
    return () => {
      clearTimeout(task)
      mql.removeEventListener("change", onChange)
    }
  }, [])

  return !!isMobile
}
