export const C = {
  bg:       '#050810',
  surface:  '#0d1117',
  card:     '#161b22',
  border:   '#21262d',
  borderHi: '#30363d',
  text:     '#e6edf3',
  textMuted:'#8b949e',
  textDim:  '#484f58',

  red:      '#dc2626',
  redDim:   '#7f1d1d',
  redGlow:  'rgba(220,38,38,0.15)',
  amber:    '#d97706',
  amberDim: '#78350f',
  blue:     '#1a56db',
  blueDim:  '#1e3a5f',
  blueGlow: 'rgba(26,86,219,0.15)',
  green:    '#16a34a',
  greenDim: '#14532d',
  purple:   '#7c3aed',
  purpleDim:'#3b0764',
  teal:     '#0891b2',
};

export const SEV = {
  Critical: { color: C.red,    bg: C.redDim,    label: 'CRITICAL' },
  High:     { color: '#f97316', bg: '#431407',   label: 'HIGH' },
  Medium:   { color: C.amber,  bg: C.amberDim,  label: 'MEDIUM' },
  Low:      { color: C.green,  bg: C.greenDim,  label: 'LOW' },
  Info:     { color: C.blue,   bg: C.blueDim,   label: 'INFO' },
};

export const STATUS = {
  Active:       { color: C.red,    label: 'Active' },
  Investigating:{ color: C.amber,  label: 'Investigating' },
  Contained:    { color: C.blue,   label: 'Contained' },
  Resolved:     { color: C.green,  label: 'Resolved' },
};

export const FONTS = {
  ui:   "'Inter', system-ui, sans-serif",
  mono: "'JetBrains Mono', 'Fira Code', monospace",
};
