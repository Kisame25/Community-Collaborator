# Community Collaborator

Burp Suite extension that provides Burp Collaborator-like functionality using [Interactsh](https://github.com/projectdiscovery/interactsh) (`oast.fun`). No Burp Professional license required.

## Features

- Suite tab for generating, injecting, and polling out-of-band callbacks
- Type-specific detail tabs (HTTP with Burp editors, DNS Query, SMTP Conversation)
- Filter by type (DNS/HTTP/SMTP) and search across all columns
- Sortable interaction table
- Right-click context: add comment, clear history, export CSV
- Single registration — all payloads share one Interactsh session

## Build

Requires JDK 11+ and the Burp Montoya API jar.

```
bash build.sh        # Linux
build.bat            # Windows
```

Output: `community-collaborator.jar`

## Usage

1. Load the jar in Burp Suite via **Extender → Extensions → Add**
2. Open the **Community Collaborator** tab
3. Click **Copy to clipboard** to generate payload(s)
4. Inject the payload into the target (parameter, header, etc.)
5. Click **Poll now** to retrieve any callbacks
