
# SentinAI - Next-Gen AI Firewall

SentinAI is a comprehensive security dashboard demonstrating how Generative AI (Gemini 2.5) can be used to detect modern cyber threats including SQL Injection, Phishing, Malware, and DDoS attacks.

## Features

*   **Dashboard Overview**: Real-time threat statistics and visualization.
*   **SQL Guard**: Heuristic analysis of SQL queries to detect injection attacks.
*   **Phishing & Malware**: Content analysis for malicious URLs and file signatures.
*   **Network Guard**: Simulated NGFW with Layer 4 (Port/IP) and Layer 7 (Content) filtering, plus AI-powered Deep Packet Inspection (DPI).
*   **DDoS Protection**: Volumetric attack simulation and mitigation logic.

## Architecture

*   **Backend**: Python FastAPI
*   **AI Engine**: Google GenAI SDK (Gemini 2.5 Flash)
*   **Frontend**: HTML5, Tailwind CSS, Chart.js, Vanilla JS
*   **Protocol**: REST API

## Installation (Local)

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Set API Key**:
    Get your key from [Google AI Studio](https://aistudio.google.com/).
    ```bash
    # Linux/Mac
    export API_KEY="your_api_key"
    # Windows PowerShell
    $env:API_KEY="your_api_key"
    ```

3.  **Run Application**:
    ```bash
    python main.py
    ```

4.  **Access**:
    Open browser to `http://localhost:8000`

## Deployment (Vercel)

This project is configured for easy deployment on Vercel.

### Prerequisites
1. A GitHub/GitLab/Bitbucket account.
2. A [Vercel](https://vercel.com) account.
3. Your Google Gemini API Key.

### Steps

1.  **Push to Git**:
    Upload this project folder to a new repository on GitHub (or your preferred provider).
    ```bash
    git init
    git add .
    git commit -m "Initial commit"
    # Add your remote origin and push
    ```

2.  **Import to Vercel**:
    *   Go to the Vercel Dashboard.
    *   Click **"Add New..."** -> **"Project"**.
    *   Select your repository.

3.  **Configure Project**:
    *   **Framework Preset**: Select "Other".
    *   **Root Directory**: Leave as `./`.
    *   **Environment Variables**:
        *   Expand the "Environment Variables" section.
        *   Key: `API_KEY`
        *   Value: `Your_Actual_Gemini_API_Key_Here`

4.  **Deploy**:
    *   Click **"Deploy"**.
    *   Vercel will install the dependencies from `requirements.txt` and start the FastAPI server.

### Note on Static Files
The `vercel.json` is configured to route all traffic to `main.py`, which handles serving the static assets (CSS/JS) via FastAPI's `StaticFiles` mount.
