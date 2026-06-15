type IconName = 'check' | 'x' | 'clock' | 'close' | 'search' | 'shield' | 'skull'

interface IconProps extends React.SVGProps<SVGSVGElement> {
  name: IconName
}

export function Icon({ name, ...props }: IconProps) {
  const stroke = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' } as const
  const paths: Record<IconName, React.ReactNode> = {
    check: <polyline {...stroke} points="3.5,8.5 6.8,11.8 12.5,4.8" />,
    x: <g {...stroke}><line x1="4" y1="4" x2="12" y2="12" /><line x1="12" y1="4" x2="4" y2="12" /></g>,
    clock: <g {...stroke}><circle cx="8" cy="8" r="5.2" /><polyline points="8,5 8,8 10,9.4" /></g>,
    close: <g {...stroke}><line x1="4.5" y1="4.5" x2="13.5" y2="13.5" /><line x1="13.5" y1="4.5" x2="4.5" y2="13.5" /></g>,
    search: <g {...stroke}><circle cx="7.2" cy="7.2" r="4.4" /><line x1="10.6" y1="10.6" x2="14" y2="14" /></g>,
    skull: <g {...stroke}><path d="M8 2.5A5 5 0 0 0 3.5 9.8V12h9V9.8A5 5 0 0 0 8 2.5Z" /><circle cx="6" cy="8" r=".7" fill="currentColor" stroke="none" /><circle cx="10" cy="8" r=".7" fill="currentColor" stroke="none" /></g>,
    shield: <path {...stroke} d="M8 2.5l4.5 1.8v3.4c0 3-2 5-4.5 6-2.5-1-4.5-3-4.5-6V4.3L8 2.5Z" />,
  }
  return <svg viewBox="0 0 16 16" aria-hidden="true" {...props}>{paths[name]}</svg>
}
