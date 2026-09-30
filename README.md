
# PE-Vision

### Browser-Based Portable Executable (PE) Analyzer

PE-Vision is a browser-based tool for inspecting Windows Portable Executable (PE) files, designed for cybersecurity students, malware analysts, and reverse-engineering enthusiasts.

🌐 **Live Demo:** https://pe-vision.netlify.app/

## Features

- PE header and metadata inspection
- Section analysis and entropy calculation
- Import and export analysis
- MD5, SHA-1, and SHA-256 file hashes
- Heuristic suspicious API indicators
- Drag-and-drop file selection
- Client-side file processing
- File size limit of 100 MB

## Supported File Types

EXE, DLL, SYS, SCR, and other files containing valid PE structures.

## Getting Started

1. Clone this repository.
2. Open the project folder.
3. Open `index.html` in a modern browser.
4. Select a PE file and click **Analyze PE**.

You can also use the Live Server extension in Visual Studio Code.

## Project Structure

```text
PE-Vision/
├── index.html
├── css/
│   └── style.css
├── js/
│   ├── app.js
│   ├── md5.js
│   └── pe-parser.js
├── netlify.toml
├── README.md
└── .gitignore
```

## Privacy and Security

PE-Vision is designed to process selected files locally in the browser rather than upload them to an analysis server.

## Disclaimer

PE-Vision is a preliminary static-analysis tool, not an antivirus engine. Suspicious API indicators do not prove a file is malicious, and the absence of indicators does not prove a file is safe. Analyze unknown files in an isolated environment.

## Deployment

The project includes a `netlify.toml` configuration for deploying the static website on Netlify.

## Author

**Akshay Sharma**

Cybersecurity | Threat Intelligence | Malware Analysis