Guide the user through setting up ZPR Policy AI Playground on localhost. Work through each step interactively — run the checks, show the output, and wait for the user before moving on.

## Steps

### 1. Check Python version
Run `python3 --version` and confirm it is 3.11 or later. If not, tell the user they need to install Python 3.11+ from python.org and stop.

### 2. Install dependencies
Run:
```
cd src/server && pip install -r requirements.txt
```
Show any errors. If installation fails, help diagnose before continuing.

### 3. Create .env
Check if `src/server/.env` already exists. If it does, tell the user and ask if they want to skip or recreate it.

If it does not exist, run:
```
cp src/server/.env.example src/server/.env
```

### 4. Generate SECRET_KEY
Run:
```
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Copy the output. Then insert it as the `SECRET_KEY` value in `src/server/.env`.

### 5. Set APP_PASSWORD
Ask the user: "Choose an APP_PASSWORD — this is the invite code anyone needs to create an account. It can be simple, e.g. your project name." Then write their answer into `src/server/.env`.

### 6. Set ANTHROPIC_API_KEY (optional)
Tell the user: "An Anthropic API key is required for AI features (Policy Studio, Policy Audit, AI Assist). If you don't have one yet, you can skip this — the app runs fully without it, but AI buttons will be disabled."

If they have a key, write it into `src/server/.env`. If not, leave the placeholder and move on.

### 7. Start the server
Run:
```
cd src/server && uvicorn server:app --reload --port 8083
```
Tell the user this will run in the foreground. Ask them to open a new terminal tab to continue if needed, or open their browser now.

### 8. First run
Tell the user to open `http://localhost:8083` in their browser.

On first run, the app redirects to `/setup`. Guide them through:
1. Enter a **username** — this becomes their root namespace (e.g. `acme` creates namespace `Acme`)
2. Enter a **password** for their account
3. Click **Create account**

The first account is automatically the admin.

### 9. Done
Confirm setup is complete. Let the user know:
- The app is running at `http://localhost:8083`
- Their `.env` is at `src/server/.env` — keep it safe, it is gitignored
- To stop the server: `Ctrl+C` in the terminal running uvicorn
- To run tests: `cd src/server && python -m pytest tests/ -q`
- For deployment instructions, see `Implementation_Guide.md`
