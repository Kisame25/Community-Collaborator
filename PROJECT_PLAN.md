# Collaborator Integration — Burp Suite Extension

## Project Overview

Add a **Collaborator tab** to Burp Repeater (next to the existing "Auto Enc" tab) that generates Burp Collaborator payloads, injects them into requests, and polls for out-of-band callbacks (DNS, HTTP, SMTP). Useful for detecting blind injection vulnerabilities, SSRF, XXE, etc.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  burp/api/montoya/collaborator/                          │
│    CollaboratorClient                                    │
│      generatePayload()  →  CollaboratorPayload           │
│      getAllInteractions() →  List<Interaction>           │
│      getAllInteractions(filter) → List<Interaction>      │
│      toString(payload)  →  full collaborator URL         │
│                                                          │
│    CollaboratorPayload                                   │
│      getPayload() → String (unique subdomain)            │
│      getDescription() → String                           │
│                                                          │
│    Interaction                                           │
│      dnsDetails()    → Optional<DnsDetails>              │
│      httpDetails()   → Optional<HttpDetails>            │
│      smtpDetails()   → Optional<SmtpDetails>            │
│      interactionId() → InteractionId                     │
│      timeStamp()     → Date                              │
│                                                          │
│    DnsDetails                                            │
│      queryType()  → DnsQueryType                         │
│      sourceIp()   → String                               │
│                                                          │
│    HttpDetails                                           │
│      request()    → HttpRequest                          │
│      response()   → HttpResponse                         │
│                                                          │
│    SmtpDetails                                           │
│      protocol()  → SmtpProtocol                          │
│      senderIp()  → String                                │
│      to()        → String                                │
│                                                          │
│    CollaboratorServer                                    │
│      location() → String (e.g., "oastify.com")           │
└──────────────────────────────────────────────────────────┘
```

---

## Features

### 1. Collaborator Tab in Repeater
- Tab labeled **"Collab"** next to "Auto Enc" in the Repeater request editor
- Contains:
  - **Generate Payload** button — creates new collaborator payload
  - **Copy** button — copies collaborator URL to clipboard
  - **Inject** button — inserts collaborator URL into a parameter value
  - **Poll** button — fetches all interactions for the current payload
  - **Payload list** — dropdown/history of previously generated payloads
  - **Interaction table** — shows DNS/HTTP/SMTP callbacks with timestamps, source IP, type
  - **Detail pane** — shows full HTTP request/response for HTTP interactions

### 2. Payload History
- Store generated payloads in memory during session
- Dropdown to switch between payloads
- Each payload shows: subdomain, creation time, interaction count

### 3. Interaction Polling
- Manual "Poll" button
- Table columns: Time, Type (DNS/HTTP/SMTP), Source IP, Query/Host
- Click a row to see details in a detail pane

### 4. Quick Inject
- Select a parameter name from a list (parsed from the current request)
- Click "Inject" — the collaborator URL replaces or appends to that parameter's value
- Option to inject in: query parameters, body parameters, headers, cookies

---

## Implementation Steps

### Step 1: Create CollaboratorClientWrapper class
- Wraps `api.collaborator().createClient()`
- Stores generated payloads in `List<CollaboratorPayload>`
- Methods:
  - `generatePayload()` → returns full collaborator URL string
  - `pollInteractions(payload)` → returns List<Interaction>
  - `getPayloads()` → returns all generated payloads this session
  - `getPayloadUrl(payload)` → returns the full URL representation

### Step 2: Create CollabTab UI (ExtensionProvidedHttpRequestEditor)
- Register via `api.userInterface().registerHttpRequestEditorProvider()`
- Only provide for `ToolType.REPEATER`
- UI layout:

```
┌──────────────────────────────────┐
│ [Generate] [Copy] [Inject] [Poll]│
│ Payload: ▼ [abc123.oastify.com] │
├──────────────────────────────────┤
│ Time        │ Type │ Source IP   │
│─────────────┼──────┼─────────────│
│ 12:34:56    │ DNS  │ 10.0.0.1    │
│ 12:34:57    │ HTTP │ 10.0.0.1    │
├──────────────────────────────────┤
│ [Detail pane: full HTTP req/res]│
└──────────────────────────────────┘
```

### Step 3: Implement backend logic in BurpExtender
- `CollabTabProvider` — implements `HttpRequestEditorProvider`
- `CollabEditor` — implements `ExtensionProvidedHttpRequestEditor`
  - `getRequest()` returns original request (no modification — this is a viewer, not a transformer)
  - `uiComponent()` returns the collab panel
- `CollaboratorService` — static/volatile state for payloads

### Step 4: Inject functionality
- When "Inject" is clicked:
  1. Get the current request from `requestResponse.request()`
  2. Parse all parameters
  3. Show a dialog or dropdown to select a parameter
  4. Replace the selected parameter's value with the collaborator URL
  5. Update the request via `withUpdatedParameters()`
  6. Burp should reflect this in the active Repeater tab

### Step 5: Interaction display
- Use `client.getAllInteractions(payload)` for polling
- Display results in a `JTable` with custom cell renderers
- Detail pane using Burp's built-in `api.userInterface().createHttpRequestEditor()`

---

## Dependencies

- **Montoya API** (already bundled) — `collaborator` package
- No external dependencies

---

## Potential Issues

| Issue | Mitigation |
|---|---|
| Async polling — UI freezes during `getAllInteractions()` | Use `SwingWorker` for polling on background thread |
| Multiple payloads across tabs | Payload list is shared (static) — each tab shows the same history |
| Inject modifies active request but user may be on "Collab" tab | The editor's `getRequest()` returns the modified request if user injects and then sends from this tab |
| Collaborator server may be slow to return interactions | Show "Polling..." status, add auto-poll every 5s option |

---

## Testing

1. **Manual test**: Load extension in Burp → go to Repeater → click "Collab" tab → Generate → Copy URL → Paste into browser → Poll → verify interaction appears
2. **SQLi blind test**: Inject collaborator URL into a SQL injection payload → send → Poll → verify DNS callback
3. **SSRF test**: Inject collaborator URL into a `url` parameter → send → Poll → verify HTTP callback
4. **Toggle OFF**: Verify Collab tab still works independently of Auto-Encode toggle
