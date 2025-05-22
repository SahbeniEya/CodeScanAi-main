# CodeScanAI

![GitHub](https://img.shields.io/github/license/AymenAzizi/AI-security-fix)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)

<p align="center">
  <div align="center" style="background-color: #0d1b2a; padding: 20px; border-radius: 10px; display: inline-block;">
    <h1 style="color: #4cc9f0; font-size: 48px; margin: 0;">CodeScanAI</h1>
    <p style="color: #4895ef; font-size: 18px; margin: 5px 0 0 0;">Secure Code. Intelligent Analysis.</p>
  </div>
</p>

CodeScanAI is a comprehensive security scanning platform that leverages AI to detect, analyze, and fix security vulnerabilities in your code. With support for multiple AI providers, advanced scanning techniques, and an intuitive interface, CodeScanAI helps developers build more secure applications with minimal effort.

## 🚀 Key Features

- **Multi-Provider AI Integration**: Connect with OpenAI, Google Gemini, Hugging Face, or your custom AI server
- **Comprehensive Security Scanning**: Perform SAST, SCA, and DAST scans from a single platform
- **Automated Fix Generation**: Get AI-powered fix suggestions for detected vulnerabilities
- **Modern Web Interface**: Intuitive dashboard with real-time scanning and results visualization
- **GitHub Integration**: Scan repositories and create pull requests with fixes
- **Futuristic Design**: Clean, responsive UI with dark and light mode support

## ✨ Detailed Features

### 🔍 Security Scanning Capabilities

- **Static Application Security Testing (SAST)**
  - Detects vulnerabilities in JavaScript, Python, Java, PHP, Ruby, and Go
  - Pattern-based detection for common security issues
  - Context-aware analysis to reduce false positives
  - Detailed vulnerability reports with severity ratings

- **Software Composition Analysis (SCA)**
  - Identifies vulnerable dependencies in package managers
  - Connects to the National Vulnerability Database (NVD) for up-to-date information
  - Detects outdated libraries and components
  - Provides remediation recommendations

- **Dynamic Application Security Testing (DAST)**
  - Scans web applications for runtime vulnerabilities
  - Detects XSS, CSRF, SQL injection, and other web vulnerabilities
  - Integration with OWASP ZAP for comprehensive testing
  - Basic scanner option for quick vulnerability checks

### 🤖 AI-Powered Features

- **Multiple AI Provider Support**
  - OpenAI integration for state-of-the-art vulnerability analysis
  - Google Gemini support for advanced code understanding
  - Hugging Face models for free and open-source options
  - Custom AI server support for self-hosted solutions

- **Intelligent Fix Generation**
  - Automatically generates fixes for detected vulnerabilities
  - Language-specific fix suggestions that maintain code functionality
  - Context-aware remediation that follows best practices
  - Fix validation to ensure vulnerabilities are properly addressed

### 🌐 Web Interface

- **Modern Dashboard**
  - Clean, intuitive user interface with dark and light modes
  - Real-time scanning progress indicators
  - Interactive vulnerability visualization
  - Detailed results with code snippets and fix suggestions

- **Scan Management**
  - Configure and launch scans from a user-friendly interface
  - Save and compare scan results over time
  - Filter and sort vulnerabilities by severity, type, and location
  - Export results in multiple formats

### 🔄 GitHub Integration

- **Repository Scanning**
  - Connect to GitHub repositories directly
  - Scan specific branches or pull requests
  - Focus on changed files for efficient scanning

- **Automated Pull Requests**
  - Create pull requests with vulnerability fixes
  - Detailed PR descriptions explaining the changes
  - Automatic branch creation for fixes

### 🛠️ Flexible Usage Options

- **Command Line Interface**
  - Run scans from the terminal with customizable options
  - Integrate into CI/CD pipelines
  - Automate security testing in development workflows

- **Scan Customization**
  - Full directory scans for comprehensive analysis
  - Changes-only scanning for efficiency
  - PR-specific scans to focus on new code
  - Configurable severity thresholds

## 🚀 Getting Started

### 📋 Prerequisites

- Python 3.10 or higher
- One of the following AI provider API keys:
  - OpenAI API key
  - Google Gemini API key
  - Hugging Face token (for free models)
  - Custom AI server access

### 💻 Installation

#### Clone the Repository

```bash
git clone https://github.com/AymenAzizi/AI-security-fix.git
cd AI-security-fix
pip install -r requirements.txt
```

### ⚙️ Configuration

Create a `.env` file in the root directory with your API keys:

```
# Choose one of the following providers
OPENAI_API_KEY=your_openai_api_key
GEMINI_API_KEY=your_gemini_api_key
HF_TOKEN=your_huggingface_token

# Optional GitHub integration
GITHUB_TOKEN=your_github_token
```

### 🖥️ Usage

#### Web Interface (Recommended)

The web interface provides the most user-friendly experience:

```bash
python run_web.py
```

Your browser will automatically open to `http://127.0.0.1:5000`

```
+---------------------------------------------+
|                                             |
|  CodeScanAI Web Interface                   |
|                                             |
|  +-------+  +-------+  +-------+  +-------+ |
|  | Scan  |  | Fix   |  | GitHub |  | Dash  | |
|  +-------+  +-------+  +-------+  +-------+ |
|                                             |
|  +-----------------------------------------+ |
|  |                                         | |
|  |  Security Scan Configuration            | |
|  |                                         | |
|  |  [ ] SAST  [ ] SCA  [ ] DAST            | |
|  |                                         | |
|  |  AI Provider: [OpenAI    ▼]             | |
|  |                                         | |
|  |  [        Start Scan        ]           | |
|  |                                         | |
|  +-----------------------------------------+ |
|                                             |
+---------------------------------------------+
```

#### Command Line Interface

For automation and CI/CD integration, use the CLI:

##### Basic Scanning

```bash
python run_cli.py --provider openai --directory path/to/your/code --sast
```

##### Complete Security Scan with Fixes

```bash
python run_cli.py --provider huggingface --directory path/to/your/code --sast --sca --fix --validate
```

##### DAST Web Application Scanning

```bash
python run_cli.py --provider gemini --dast --target-url "https://example.com"
```

##### GitHub Repository Scanning

```bash
python run_cli.py --provider openai --repo "username/repository" --github-token "your_token" --sast --fix --create-pr
```

### 🎮 Web Interface Features

The web interface offers an intuitive way to interact with CodeScanAI:

1. **Home Page**: Configure scan settings and AI providers
2. **Scan Page**: Launch and monitor security scans
3. **Results Page**: View detailed vulnerability reports with fix suggestions
4. **GitHub Integration**: Connect to repositories and create fix PRs
5. **Dashboard**: Visualize security metrics and trends

### 📊 CLI Arguments

| Argument       | Description                                | Required | Default        |
|----------------|--------------------------------------------|----------|----------------|
| `provider`     | AI provider (openai, gemini, huggingface, custom) | Yes | - |
| `directory`    | Directory to scan                          | No       | `.` (current)  |
| `sast`         | Enable SAST scanning                       | No       | `false`        |
| `sca`          | Enable SCA scanning                        | No       | `false`        |
| `dast`         | Enable DAST scanning                       | No       | `false`        |
| `target_url`   | Target URL for DAST scanning               | No       | -              |
| `fix`          | Generate vulnerability fixes                | No       | `false`        |
| `validate`     | Validate generated fixes                   | No       | `false`        |
| `repo`         | GitHub repository (username/repo)          | No       | -              |
| `github_token` | GitHub API token                           | No       | -              |
| `create-pr`    | Create a pull request with fixes           | No       | `false`        |
| `model`        | Specific AI model to use                   | No       | Provider default |
| `host`         | Custom AI server host                      | No       | -              |
| `port`         | Custom AI server port                      | No       | -              |

## 🔧 Technical Details

### 💻 Languages & Technologies

CodeScanAI is built using the following technologies:

- **Python**: Core application logic, security scanning, and AI integration
- **JavaScript**: Frontend interactivity and dynamic UI components
- **HTML/CSS**: Web interface structure and styling
- **Flask**: Web framework for the application
- **Bootstrap**: Frontend component library with custom styling
- **SQLite**: Local database for storing scan results and configurations

### 📂 Project Structure

```
codescanai/                # Main application package
├── web/                   # Web interface components
│   ├── app.py             # Flask application entry point
│   ├── static/            # Static assets
│   │   ├── css/           # Stylesheets (including futuristic.css)
│   │   ├── js/            # JavaScript files
│   │   └── img/           # Images and icons
│   └── templates/         # HTML templates
│       ├── base.html      # Base template with common elements
│       ├── index.html     # Home page
│       ├── scan.html      # Scan configuration page
│       └── results.html   # Results display page
│
core/                      # Core functionality
├── code_scanner/          # Code scanning logic
├── scanners/              # Security scanners
│   ├── sast_scanner.py    # Static analysis scanner
│   ├── dast_scanner.py    # Dynamic analysis scanner
│   ├── sca_scanner.py     # Software composition analysis
│   └── unified_scanner.py # Combined scanning orchestration
├── providers/             # AI provider integrations
│   ├── open_ai_provider.py       # OpenAI integration
│   ├── google_gemini_ai_provider.py # Google Gemini integration
│   ├── huggingface_provider.py   # Hugging Face integration
│   └── custom_ai_provider.py     # Custom AI server integration
├── fixers/                # Vulnerability fix generation
├── github_integration/    # GitHub API integration
├── reporting/             # Report generation
└── utils/                 # Utility functions
```

### 🔐 Security Scanning Approach

CodeScanAI employs a multi-layered approach to security scanning:

1. **Pattern Matching**: Identifies known vulnerability patterns in code
2. **Semantic Analysis**: Understands code context to reduce false positives
3. **Dependency Checking**: Compares dependencies against vulnerability databases
4. **AI Analysis**: Uses AI models to detect complex vulnerabilities
5. **Dynamic Testing**: Tests running applications for runtime vulnerabilities

### 🧠 AI Integration Architecture

The AI integration is designed with flexibility in mind:

1. **Provider Abstraction**: Common interface for all AI providers
2. **Prompt Engineering**: Carefully crafted prompts for optimal vulnerability detection
3. **Context Management**: Efficient handling of code context for accurate analysis
4. **Response Parsing**: Structured parsing of AI responses into actionable results
5. **Fallback Mechanisms**: Graceful degradation when AI services are unavailable

## 🛣️ Roadmap

### Short-term Goals

- **Enhanced C/C++ Support**: Improve detection of memory safety vulnerabilities
- **Performance Optimization**: Reduce scan times and resource usage
- **Expanded Test Coverage**: Increase automated test coverage for core components
- **Docker Deployment**: Simplified deployment with Docker containers

### Long-term Vision

- **Machine Learning Enhancement**: Train custom models on vulnerability patterns
- **IDE Integrations**: Extensions for VSCode, JetBrains IDEs, and more
- **Additional Git Providers**: Support for GitLab, Bitbucket, and Azure DevOps
- **Enterprise Features**: Role-based access control and team collaboration
- **API Expansion**: Comprehensive REST API for third-party integrations

## 🤝 Contributing

Contributions are welcome and appreciated! Here's how you can contribute:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add some amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a pull request**

Please make sure to update tests as appropriate and follow the code style guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [OWASP](https://owasp.org/) for security best practices and guidelines
- [OpenAI](https://openai.com/), [Google](https://ai.google.dev/), and [Hugging Face](https://huggingface.co/) for AI capabilities
- All contributors who have helped improve this project

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/AymenAzizi">Aymen Azizi</a>
</p>