# OpenClaw Railway Template (Clawbot)

This repository provides a 1-click deployment for **OpenClaw** (formerly Clawbot/Moltbot) on Railway. It includes a web-based setup wizard to configure your AI assistant without using the terminal.

## Features

- **Setup Wizard**: Access `/setup` to configure your AI provider (OpenAI, Anthropic, Gemini, etc.).
- **Persistence**: Uses Railway Volumes to persist your configuration and workspace.
- **Messaging Integration**: Easily setup Telegram and Discord bots.
- **Web UI**: Access the OpenClaw Control UI directly in your browser.

## Deployment Instructions

1.  **Clone or Fork** this repository.
2.  **Create a Railway Project** and connect it to your repository.
3.  **Add a Volume**: Mount a volume at `/data`.
4.  **Set Variables**:
    - `SETUP_PASSWORD`: A password for the `/setup` page (Required).
    - `OPENCLAW_STATE_DIR`: `/data/.openclaw` (Recommended).
    - `OPENCLAW_WORKSPACE_DIR`: `/data/workspace` (Recommended).
5.  **Enable Public Networking**: Railway will assign a domain.

## Getting Started

1.  Visit `https://<your-app>.up.railway.app/setup`.
2.  Log in with your `SETUP_PASSWORD`.
3.  Follow the instructions to configure your AI provider and channels.
4.  Once configured, visit the root URL to use the OpenClaw UI.

## Support

- [OpenClaw GitHub](https://github.com/openclaw/openclaw)
- [Railway Docs](https://docs.railway.com)
