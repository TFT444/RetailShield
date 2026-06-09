const S = {
  Active:        { color:'#DC2626', bg:'rgba(220,38,38,0.12)',  border:'rgba(220,38,38,0.25)'  },
  Investigating: { color:'#D97706', bg:'rgba(217,119,6,0.12)',  border:'rgba(217,119,6,0.25)'  },
  Contained:     { color:'#2563EB', bg:'rgba(37,99,235,0.12)',  border:'rgba(37,99,235,0.25)'  },
  Resolved:      { color:'#16A34A', bg:'rgba(22,163,74,0.12)',  border:'rgba(22,163,74,0.25)'  },
  Monitored:     { color:'#0891B2', bg:'rgba(8,145,178,0.12)',  border:'rgba(8,145,178,0.25)'  },
  Compliant:     { color:'#16A34A', bg:'rgba(22,163,74,0.12)',  border:'rgba(22,163,74,0.25)'  },
  Submitted:     { color:'#16A34A', bg:'rgba(22,163,74,0.12)',  border:'rgba(22,163,74,0.25)'  },
  Acknowledged:  { color:'#0891B2', bg:'rgba(8,145,178,0.12)',  border:'rgba(8,145,178,0.25)'  },
  Closed:        { color:'#5A6478', bg:'rgba(90,100,120,0.12)', border:'rgba(90,100,120,0.25)' },
  'Pending Review':{ color:'#D97706', bg:'rgba(217,119,6,0.12)',border:'rgba(217,119,6,0.25)'  },
  Open:          { color:'#F97316', bg:'rgba(249,115,22,0.12)', border:'rgba(249,115,22,0.25)' },
  Info:          { color:'#0891B2', bg:'rgba(8,145,178,0.12)',  border:'rgba(8,145,178,0.25)'  },
};

export default function StatusBadge({ status }) {
  const s = S[status] || S.Monitored;
  return (
    <span style={{
      display:'inline-flex', alignItems:'center', gap:'5px',
      padding:'2px 8px', borderRadius:'var(--r-badge)',
      fontSize:'11px', fontWeight:600, letterSpacing:'0.05em',
      color:s.color, background:s.bg, border:`1px solid ${s.border}`,
      whiteSpace:'nowrap', flexShrink:0,
    }}>
      <span style={{ width:5, height:5, borderRadius:'50%', background:s.color, flexShrink:0 }} />
      {status}
    </span>
  );
}
