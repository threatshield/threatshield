# ThreatShield — Frontend

React/TypeScript frontend for ThreatShield. Requires the Flask backend running on port 5001.

## Development

```bash
npm install
npm start        # dev server on http://localhost:3000
npm run build    # production build
npm test         # run tests
```

API calls are proxied to `http://localhost:5001` in development (configured in `package.json` proxy field). In production, `REACT_APP_API_URL_PROD` controls the API base URL.

## Environment variables

Copy `.env.example` to `.env` and set values:

```env
REACT_APP_DEPLOYMENT_TYPE=dev
REACT_APP_API_URL_DEV=http://localhost:5001/api
REACT_APP_API_URL_PROD=https://threatshield.example.com/api
REACT_APP_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
```

## Pages

| Route | Component | Description |
|-------|-----------|-------------|
| `/` | `LandingPage` | Public landing page |
| `/login` | `LoginPage` | Google OAuth sign-in |
| `/home` | `Home` | Post-login dashboard |
| `/queue` | `Queue` | Assessment queue management |
| `/threat-model` | `ThreatModel` | STRIDE threat model view |
| `/dread` | `Dread` | DREAD risk scoring |
| `/mitigation` | `Mitigation` | Mitigation recommendations |
| `/attack-tree` | `AttackTree` | Attack tree visualization |
| `/test-cases` | `ViewSecurityTestCases` | ASVS security test cases |
| `/chat` | `Chat` | Natural language Q&A over assessments |
| `/report` | `Report` / `ReportList` | Report views |
| `/analytics` | `Analytics` | Risk metrics dashboard |
| `/admin` | `AdminDashboard` | LLM config, admin management, logs |
| `/settings` | `Settings` | Pre-context and app settings |
| `/integrations` | `Integrations` | MCP server management |
| `/feedback` | `FeedbackPage` / `FeedbackList` | User feedback |

## Auth flow

1. User clicks "Sign in with Google" on `/login`
2. Google returns an ID token
3. Frontend POSTs it to `/api/auth/google`
4. Backend returns a signed Bearer token (7-day TTL), stored as `ts_auth_token` in `localStorage`
5. All subsequent API requests include `Authorization: Bearer <token>`

## Key context providers

- `AuthContext` — current user, login/logout
- `AssessmentContext` — active assessment ID/name + background status polling
- `ThemeContext` — dark/light mode

## Project structure

```
src/
├── pages/         # One component per route (see table above)
├── components/    # Shared UI components
│   └── common/    # ASVSTestCases, AttackTree, etc.
├── context/       # AuthContext, AssessmentContext, ThemeContext
├── services/      # api.ts — all Axios/fetch calls to the backend
└── App.tsx        # React Router setup
```
