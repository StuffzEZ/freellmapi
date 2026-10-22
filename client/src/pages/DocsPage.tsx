import { useState } from 'react'
import { BookOpen, ChevronDown } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const SECTIONS = [
  {
    id: 'start',
    title: 'Getting started',
    body: `Add at least one provider key on Keys, then test a request in the Playground. Your unified API key is shown in the Keys page header — point your OpenAI SDK at http://localhost:3001/v1 with that key.`,
  },
  {
    id: 'models',
    title: 'Model types & selection',
    body: `Use a specific model id, or let the router choose: "auto" follows your active chain; "auto:fast"/"auto:fastest" favors speed; "auto:smart"/"auto:smartest" favors intelligence; "auto:reliable" favors success rate; "auto:cheap" is budget-leaning; "auto:<profile>" routes through a named profile; "fusion" fans out to a panel and synthesizes one answer.`,
  },
  {
    id: 'custom',
    title: 'Custom API (OpenAI-compatible)',
    body: `On Keys → Custom, add any OpenAI-compatible endpoint (llama.cpp, LM Studio, vLLM, Ollama, remote gateways, or OpenRouter). Use Fetch models to import its model list. Group endpoints with a group label and route with model#group (e.g. custom:deepseek-v3.1#work-relays).`,
  },
  {
    id: 'authentik',
    title: 'Multi-user login (Authentik)',
    body: `Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI in .env to enable OIDC. Each user gets an isolated database; create revocable API keys with per-user token limits in Settings → API access. When OIDC is enabled, local password login/setup is disabled.`,
  },
  {
    id: 'vscode',
    title: 'VS Code integration',
    body: `Point Continue/Cline/Roo/Kilo/Copilot at http://localhost:3001/v1 with your unified key, or run npx freellmapi setup-cline / setup-roo / setup-kilo and reload VS Code. Continue ghost-text uses /v1/completions with useLegacyCompletionsEndpoint: true.`,
  },
  {
    id: 'openrouter',
    title: 'OpenRouter models',
    body: `OpenRouter is a built-in provider (:free suffix marks zero-cost routes). Add more OpenRouter models through the custom provider using Fetch models, or add your OpenRouter key on Keys and pick models from the catalog.`,
  },
]

export default function DocsPage() {
  const [open, setOpen] = useState<string | null>(SECTIONS[0].id)
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <BookOpen className="size-5" />
        <h1 className="text-2xl font-semibold">Documentation</h1>
      </div>
      <p className="text-sm text-muted-foreground">
        In-app reference. Full guides live in the repo docs/ folder.
      </p>
      <div className="space-y-3">
        {SECTIONS.map(s => (
          <Card key={s.id}>
            <CardHeader className="cursor-pointer" onClick={() => setOpen(open === s.id ? null : s.id)}>
              <CardTitle className="flex items-center justify-between text-base">
                {s.title}
                <ChevronDown className={`size-4 transition ${open === s.id ? 'rotate-180' : ''}`} />
              </CardTitle>
            </CardHeader>
            {open === s.id && (
              <CardContent>
                <p className="text-sm text-muted-foreground whitespace-pre-wrap">{s.body}</p>
              </CardContent>
            )}
          </Card>
        ))}
      </div>
    </div>
  )
}
