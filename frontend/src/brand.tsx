// Brand pieces: shield logo, wordmark, line icons and the animated login hero. Pure SVG, no image downloads.
export const ICONS = {
  grid: "M3 3h7v7H3z M14 3h7v7h-7z M14 14h7v7h-7z M3 14h7v7H3z",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  shieldcheck: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4",
  flask: "M10 2v7.5L4.5 19a2 2 0 0 0 1.8 3h11.4a2 2 0 0 0 1.8-3L14 9.5V2 M8.5 2h7 M7 16h10",
  lock: "M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4",
  chart: "M3 3v18h18 M7 14l4-4 3 3 5-6",
  check: "M22 11.08V12a10 10 0 1 1-5.93-9.14 M22 4 12 14.01l-3-3",
  ban: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M4.9 4.9l14.2 14.2",
  key: "M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8z M11.4 11.6 15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4",
  user: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M16 11l2 2 4-4",
  cloud: "M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9z",
  server: "M2 4h20v6H2z M2 14h20v6H2z M6 7h.01 M6 17h.01",
  laptop: "M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9 M2 20h20 M2 16h20",
  network: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M12 2v4 M12 18v4 M2 12h4 M18 12h4 M5 5l3 3 M16 16l3 3 M19 5l-3 3 M8 16l-3 3",
  alert: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z M12 9v4 M12 17h.01",
  clock: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 6v6l4 2",
  idcard: "M3 5h18v14H3z M8 11a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M5.5 16c.5-2 5.5-2 5.5 0 M14 9h4 M14 13h4",
  search: "M11 3a8 8 0 1 0 0 16 8 8 0 0 0 0-16z M21 21l-4.3-4.3",
} as const;
export type IconName = keyof typeof ICONS;

export const Icon = ({ name, size = 20 }: { name: IconName; size?: number }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d={ICONS[name]} />
  </svg>
);

export const Logo = ({ size = 36 }: { size?: number }) => (
  <svg className="logo-svg" viewBox="0 0 64 64" width={size} height={size} aria-hidden="true">
    <defs>
      <linearGradient id="lg1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#22d3ee" /><stop offset=".55" stopColor="#3b82f6" /><stop offset="1" stopColor="#a855f7" /></linearGradient>
    </defs>
    <path d="M32 4 54 12v18c0 14-10 24-22 30C20 54 10 44 10 30V12z" fill="rgba(20,40,110,.55)" stroke="url(#lg1)" strokeWidth="3" strokeLinejoin="round" />
    <path d="M22 22h20L26 42h16" fill="none" stroke="#fff" strokeWidth="5.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M5 41c9 13 41 14 56-12" fill="none" stroke="url(#lg1)" strokeWidth="2.5" strokeLinecap="round" opacity=".9" />
  </svg>
);

export const Wordmark = ({ size = 22 }: { size?: number }) => (
  <span className="wm" style={{ fontSize: size }}>Zero<b>Guard</b></span>
);

const ORBIT: { n: IconName; x: number; y: number; d: number }[] = [
  { n: "user", x: 110, y: 120, d: 0 }, { n: "cloud", x: 450, y: 85, d: 1.2 }, { n: "server", x: 508, y: 255, d: 2.4 },
  { n: "laptop", x: 440, y: 415, d: 3.1 }, { n: "network", x: 70, y: 335, d: 4 },
];

export function HeroShield() {
  return (
    <svg className="hero-art" viewBox="0 0 580 520" role="img" aria-label="ZeroGuard shield">
      <defs>
        <linearGradient id="hs-fill" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#38bdf8" stopOpacity=".55" /><stop offset=".55" stopColor="#2563eb" stopOpacity=".45" /><stop offset="1" stopColor="#7c3aed" stopOpacity=".7" /></linearGradient>
        <linearGradient id="hs-edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#67e8f9" /><stop offset=".5" stopColor="#60a5fa" /><stop offset="1" stopColor="#c084fc" /></linearGradient>
        <linearGradient id="hs-lock" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#bfe6ff" /><stop offset="1" stopColor="#5aa9f5" /></linearGradient>
        <radialGradient id="hs-floor" cx=".5" cy=".5" r=".5"><stop offset="0" stopColor="#38bdf8" stopOpacity=".7" /><stop offset="1" stopColor="#38bdf8" stopOpacity="0" /></radialGradient>
        <filter id="glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="6" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
      </defs>
      <circle className="spin" cx="290" cy="250" r="215" fill="none" stroke="#7dd3fc" strokeOpacity=".55" strokeWidth="3" strokeDasharray="1 9" strokeLinecap="round" />
      <circle className="spin rev" cx="290" cy="250" r="180" fill="none" stroke="#a78bfa" strokeOpacity=".4" strokeWidth="2" strokeDasharray="2 12" strokeLinecap="round" />
      <circle cx="290" cy="250" r="235" fill="none" stroke="#60a5fa" strokeOpacity=".15" />
      {ORBIT.map((o) => <line key={o.n} x1="290" y1="255" x2={o.x} y2={o.y} stroke="#60a5fa" strokeOpacity=".22" strokeDasharray="3 5" />)}
      <ellipse cx="290" cy="448" rx="230" ry="46" fill="url(#hs-floor)" className="pulse" />
      {[[190, 34], [150, 26], [110, 18]].map(([rx, ry], i) => <ellipse key={rx} cx="290" cy={440 - i * 4} rx={rx} ry={ry} fill="rgba(8,20,60,.6)" stroke="url(#hs-edge)" strokeWidth={i === 2 ? 2.5 : 1.5} strokeOpacity={0.9 - i * 0.2} />)}
      <g filter="url(#glow)" className="pulse">
        <path d="M290 105 405 148v118c0 74-52 120-115 148-63-28-115-74-115-148V148z" fill="url(#hs-fill)" stroke="url(#hs-edge)" strokeWidth="4" strokeLinejoin="round" />
      </g>
      <path d="M290 130 385 164v102c0 62-44 101-95 124-51-23-95-62-95-124V164z" fill="none" stroke="#bfe6ff" strokeOpacity=".3" strokeWidth="1.5" />
      <g stroke="#bfe6ff" strokeOpacity=".35" strokeWidth="1" fill="#e0f2fe">
        <polyline fill="none" points="215,190 255,170 300,200 350,175 372,215 330,250 372,290 320,330 290,372 255,330 215,290 240,245 215,190" />
        <polyline fill="none" points="255,170 240,245 300,200 330,250 255,330 320,330" />
        {[[215, 190], [255, 170], [300, 200], [350, 175], [372, 215], [330, 250], [372, 290], [320, 330], [255, 330], [215, 290], [240, 245]].map(([x, y]) => <circle key={`${x}${y}`} cx={x} cy={y} r="2.8" stroke="none" fillOpacity=".8" />)}
      </g>
      <g filter="url(#glow)">
        <path d="M262 262v-22a28 28 0 0 1 56 0v22" fill="none" stroke="url(#hs-lock)" strokeWidth="13" strokeLinecap="round" />
        <rect x="247" y="258" width="86" height="72" rx="13" fill="url(#hs-lock)" />
        <circle cx="290" cy="288" r="9" fill="#0b2a66" /><rect x="286" y="291" width="8" height="20" rx="3" fill="#0b2a66" />
      </g>
      {ORBIT.map((o) => (
        <g key={o.n} className="bub" style={{ animationDelay: `${o.d}s` }} transform={`translate(${o.x} ${o.y})`}>
          <g className="bub-in" style={{ animationDelay: `${o.d}s` }}>
            <circle r="42" fill="url(#hs-floor)" opacity=".5" />
            <circle r="31" fill="rgba(10,24,70,.85)" stroke="url(#hs-edge)" strokeWidth="2" filter="url(#glow)" />
            <path d={ICONS[o.n]} transform="translate(-16 -16) scale(1.33)" fill="none" stroke="#bfe6ff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </g>
        </g>
      ))}
    </svg>
  );
}
