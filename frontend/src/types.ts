export interface Session {
  id: string;
  _fullId: string;
  user: string;
  country: string;
  agent: string;
  status: string;
  risk: number;
  msgs: number;
  technique: string | null;
  startedAt: number;
}

export interface Attack {
  id: string;
  session: string;
  technique: string;
  severity: string;
  signature: string;
  ts: string;
  fakeServed: string;
  blocked?: boolean;
}

export interface Persona {
  id: string;
  name: string;
  status: string;
  sessionsServed: number;
  accent: string;
  glyph: string;
  summary: string;
  behaviour: string;
  fakePrompt: string;
  triggers: string[];
  fakeDatasets: string[];
}
