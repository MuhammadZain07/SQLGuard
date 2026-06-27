# SQLGuard - SQL Injection Scanner & Security Dashboard

SQLGuard is an automated web application vulnerability scanner specifically designed to detect, analyze, and report SQL Injection (SQLi) vulnerabilities. Featuring a modern, real-time interactive dashboard, SQLGuard crawls target web applications, identifies entry points, performs controlled injection testing, and presents a visual analysis of security findings.

---

## 🛠️ Tech Stack

SQLGuard is built on a modern, robust asynchronous stack:

- **Backend Framework:** Python & Flask
- **Task Queue & Async Processing:** Celery
- **Message Broker & Cache:** Redis
- **Database ORM:** SQLAlchemy (supporting PostgreSQL / SQLite)
- **Frontend Presentation:** HTML5, CSS3 (Vanilla), JavaScript (ES6+)
- **Data Visualization:** Chart.js
- **Containerization:** Docker & Docker Compose

---

## 🚀 Key Scanner Features

- **SQL Injection Detection Engines:**
  - **Error-Based SQLi:** Detects vulnerabilities by parsing detailed database server error messages returned in HTML responses.
  - **Boolean-Based Blind SQLi:** Identifies vulnerabilities by comparing variations in application response content for true vs. false SQL conditions.
  - **Time-Based Blind SQLi:** Injects delay payloads (e.g., `sleep`) and monitors latency spikes to confirm SQL execution.
  - **Union-Based SQLi:** Leverages `UNION SELECT` operations to retrieve schema metadata and table content.
- **Intelligent Crawler:** Discovers web pages recursively, extracts HTML forms, maps query parameters, and catalogs inputs for targeted scanning.
- **Interactive Security Dashboard:** Displays real-time scan progress, live console output logs, historical summaries, vulnerabilities classification charts, and cached RSS cybersecurity feeds.

---

## 📦 Installation & Configuration

Follow these steps to set up SQLGuard locally:

### 1. Clone the Repository
```bash
git clone https://github.com/MuhammadZain07/SQLGuard.git
cd SQLGuard
```

### 2. Set Up a Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a file named `.env` in the root directory and define the following variables:
```env
SECRET_KEY=your_super_secret_jwt_and_session_signing_key
DATABASE_URL=sqlite:///sqlguard.db
REDIS_URL=redis://localhost:6379/0
```
