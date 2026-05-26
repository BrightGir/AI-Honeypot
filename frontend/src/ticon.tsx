export const TIcon = ({ name, size = 14 }: any) => {
  const p: any = {
    play:    <polygon points="5 3 19 12 5 21" />,
    pause:   <><rect x="5" y="4" width="4" height="16" /><rect x="15" y="4" width="4" height="16" /></>,
    rewind:  <><polygon points="11 19 2 12 11 5 11 19" /><polygon points="22 19 13 12 22 5 22 19" /></>,
    forward: <><polygon points="13 19 22 12 13 5 13 19" /><polygon points="2 19 11 12 2 5 2 19" /></>,
    stepf:   <><line x1="19" y1="5" x2="19" y2="19" /><polygon points="5 5 19 12 5 19" /></>,
    stepb:   <><line x1="5" y1="5" x2="5" y2="19" /><polygon points="19 5 5 12 19 19" /></>,
    arrow:   <path d="M5 12h14M13 6l6 6-6 6" />,
    plus:    <path d="M12 5v14M5 12h14" />,
    inject:  <><path d="M12 19V5" /><path d="m5 12 7 7 7-7" /></>,
    burn:    <path d="M12 2s4 4 4 8a4 4 0 0 1-8 0c0-4 4-8 4-8z" />,
    alert:   <><path d="M12 9v4" /><path d="M12 17h.01" /><path d="m4.86 19 7.07-12.25a1 1 0 0 1 1.74 0L20.74 19a1 1 0 0 1-.87 1.5H5.73A1 1 0 0 1 4.86 19z" /></>,
    eye:     <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></>,
    download:<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m7 10 5 5 5-5" /><path d="M12 15V3" /></>,
    flag:    <><path d="M4 22V4a1 1 0 0 1 1-1h13l-2 5 2 5H5" /><path d="M4 22H2" /></>,
    settings:<><circle cx="12" cy="12" r="3" /><path d="M12 1v6m0 10v6M4.22 4.22l4.24 4.24m7.08 7.08 4.24 4.24M1 12h6m10 0h6M4.22 19.78l4.24-4.24m7.08-7.08 4.24-4.24" /></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {p[name]}
    </svg>
  );
};
