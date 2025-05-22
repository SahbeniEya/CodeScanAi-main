"""
This module defines the Hugging Face Provider.
This is one of the supported AI Providers, and implements the BaseAIProvider abstract class.
It uses the Hugging Face Inference API to scan code for security vulnerabilities.
"""

import os
import requests
import logging
import dotenv
import re
from huggingface_hub import InferenceClient
from typing import List, Optional, Dict, Any, Union
from tenacity import retry, stop_after_attempt, wait_exponential

from core.providers.base_ai_provider import BaseAIProvider
from core.scanners.sast_scanner import Vulnerability
# Import fix generators with type ignore comments to suppress type checking errors
from core.providers.fix_generators import get_fix_generator_for_vulnerability  # type: ignore
from core.providers.python_fix_generators import get_python_fix_generator_for_vulnerability  # type: ignore

# Load environment variables from .env file
dotenv.load_dotenv()


class HuggingFaceProvider(BaseAIProvider):
    """Provider that interacts with the Hugging Face Inference API."""

    def __init__(self, model):
        """Initializes the HuggingFaceProvider with the given model.

        Args:
            model (str): The model ID to use for inference. If not provided,
                         a default model will be used.
        """
        # Use environment variable or fallback to the provided token
        self.token = os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_TOKEN") or ""
        # Log token status (without revealing the actual token)
        if self.token:
            logging.info("Hugging Face token found in environment variables")
        else:
            logging.warning("No Hugging Face token found in environment variables. API calls may fail.")

        # Default to a model that works well with the Hugging Face Inference API
        self.model = model if model else "mistralai/Mistral-7B-Instruct-v0.3"
        # Initialize client with token
        self.client = InferenceClient(token=self.token)
        # Set request timeout
        self.timeout = 120  # 120 seconds timeout for larger models

    def scan_code(self, code_summary):
        """Scans the code using Hugging Face Inference API.

        Args:
            code_summary (str): The code to scan for vulnerabilities.

        Returns:
            str: The analysis result from the model.
        """
        try:
            # Use a direct API call to the Hugging Face Inference API
            # This is a more reliable approach than using the client
            # Use the model specified in the constructor
            API_URL = f"https://api-inference.huggingface.co/models/{self.model}"
            headers = {"Authorization": f"Bearer {self.token}"}
            logging.info(f"Using model: {self.model} for code scanning")

            # Truncate code summary if it's too long
            truncated_code = code_summary[:1000] + "\n\n[Code truncated due to length...]" if len(code_summary) > 1000 else code_summary

            prompt = """You are an expert in software security analysis,
            adept at identifying and explaining potential vulnerabilities in code. You will be
            given complete code snippets from various applications. Your task is to analyze
            the provided code, pinpoint potential security risks, and offer clear suggestions
            for enhancing the application's security posture. Focus on the critical issues that
            could impact the overall security of the application.

            CODE TO ANALYZE:
            """

            # Combine prompt with truncated code summary
            full_prompt = prompt + truncated_code

            # Make a direct API call
            # For flan-t5-small, we need to use a different format
            payload = {"inputs": full_prompt}
            response = requests.post(API_URL, headers=headers, json=payload, timeout=self.timeout)
            response.raise_for_status()

            # Extract the generated text
            result = response.json()[0]["generated_text"]

            # Return the result
            return result
        except Exception as e:  # pylint: disable=W0718
            return f"Error occurred: {e}"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate_fix(self, vulnerability: Vulnerability) -> Optional[str]:
        """Generates a fix for a specific vulnerability using Hugging Face Inference API.

        Args:
            vulnerability (Vulnerability): The vulnerability to generate a fix for.

        Returns:
            Optional[str]: The suggested fix, or None if no fix could be generated.
        """
        try:
            # Log the model being used
            logging.info(f"Using model: {self.model} for vulnerability fix generation")

            # Create a prompt that includes the vulnerability details and code
            # Format for Mistral-7B-Instruct-v0.3
            prompt = f"""<s>[INST] You are an expert in software security. Fix the following vulnerability:

Vulnerability ID: {vulnerability.id}
Severity: {vulnerability.severity}
Description: {vulnerability.description}
File: {vulnerability.file_path}
Line: {vulnerability.line_number}

Vulnerable code:
```
{vulnerability.code}
```

Provide only the fixed code without any explanation. The fix should address the security issue while maintaining the original functionality. [/INST]"""

            # Use the InferenceClient directly
            result = self.client.text_generation(
                prompt,
                model=self.model,
                max_new_tokens=500,
                temperature=0.2,
                do_sample=True
            )

            # Clean up the result (remove markdown code blocks if present)
            if "```" in result:
                # Extract code between the first and last code block markers
                start_idx = result.find("```") + 3
                # Skip the language identifier if present
                if result[start_idx:].startswith("python") or result[start_idx:].startswith("py"):
                    start_idx = result.find("\n", start_idx) + 1
                end_idx = result.rfind("```")
                if start_idx < end_idx:
                    result = result[start_idx:end_idx].strip()

            return result
        except Exception as e:  # pylint: disable=W0718
            print(f"Error generating fix: {e}")
            return None

    def generate_fixes_for_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Generates fixes for a list of vulnerabilities.

        Args:
            vulnerabilities (List[Vulnerability]): The vulnerabilities to generate fixes for.

        Returns:
            List[Vulnerability]: The vulnerabilities with fix suggestions added.
        """
        for vuln in vulnerabilities:
            try:
                logging.info(f"Generating fix for vulnerability in {vuln.file_path}:{vuln.line_number}")

                # Try to use our custom Python fix generators first
                if vuln.file_path.endswith(('.py', '.pyw')):
                    fix = get_python_fix_generator_for_vulnerability(vuln)
                    if fix:
                        vuln.fix_suggestion = fix
                        logging.info(f"Successfully generated custom Python fix for vulnerability in {vuln.file_path}:{vuln.line_number}")
                        continue

                # If no custom fix was generated, fall back to the AI model
                fix = self.generate_fix(vuln)
                if fix:
                    vuln.fix_suggestion = fix
                    logging.info(f"Successfully generated fix for vulnerability in {vuln.file_path}:{vuln.line_number}")
                else:
                    # If AI model fails, try to generate a generic fix based on vulnerability type
                    if 'sql' in vuln.id.lower() or 'sql injection' in vuln.description.lower():
                        if vuln.file_path.endswith('.py'):
                            vuln.fix_suggestion = "# Use parameterized queries instead of string concatenation\ncursor.execute(\"SELECT * FROM users WHERE username = ? AND password = ?\", [username, password])"
                        else:
                            vuln.fix_suggestion = "// Use parameterized queries instead of string concatenation\nconnection.query(\"SELECT * FROM users WHERE username = ?\", [username]);"
                    elif 'timeout' in vuln.id.lower() or 'b113' in vuln.id.lower():
                        vuln.fix_suggestion = "# Always include a timeout parameter with requests\nresponse = requests.post(api_url, headers=headers, json=payload, timeout=30)"
                    elif 'flask' in vuln.id.lower() or 'debug' in vuln.id.lower() or 'b201' in vuln.id.lower():
                        vuln.fix_suggestion = "# Don't use debug=True in production\nif __name__ == '__main__':\n    app.run(debug=False)"
                    elif 'command' in vuln.id.lower() or 'command injection' in vuln.description.lower():
                        if vuln.file_path.endswith('.py'):
                            vuln.fix_suggestion = "# Use subprocess with arguments as a list instead of shell=True\nimport subprocess\nsubprocess.run(['command', param1, param2], check=True)"
                        elif vuln.file_path.endswith('.java'):
                            vuln.fix_suggestion = "// Use ProcessBuilder instead of Runtime.exec with user input\nList<String> commands = new ArrayList<>();\ncommands.add(\"command\");\ncommands.add(sanitizedParam);\nProcessBuilder processBuilder = new ProcessBuilder(commands);\nProcess process = processBuilder.start();"
                        else:
                            vuln.fix_suggestion = "// Use a safer method for executing commands\nconst { execFile } = require('child_process');\nexecFile('command', [param1, param2], (error, stdout, stderr) => {\n  if (error) {\n    console.error(`Error: ${error}`);\n    return;\n  }\n  console.log(stdout);\n});"
                    elif 'xss' in vuln.id.lower() or 'cross-site scripting' in vuln.description.lower():
                        if vuln.file_path.endswith('.py'):
                            vuln.fix_suggestion = "# Use HTML escaping to prevent XSS\nimport html\nsafe_output = html.escape(user_input)\nprint(safe_output)"
                        elif vuln.file_path.endswith('.java'):
                            vuln.fix_suggestion = "// Use ESAPI encoder to prevent XSS\nimport org.owasp.esapi.ESAPI;\n\n// Instead of:\n// out.println(userInput);\n\n// Use:\nout.println(ESAPI.encoder().encodeForHTML(userInput));"
                        else:
                            vuln.fix_suggestion = "// Use appropriate encoding to prevent XSS\nconst safeOutput = document.createTextNode(userInput);\nelement.appendChild(safeOutput);"
                    elif 'path traversal' in vuln.id.lower() or 'path' in vuln.id.lower():
                        if vuln.file_path.endswith('.py'):
                            vuln.fix_suggestion = "# Prevent path traversal by using os.path functions\nimport os.path\nsafe_path = os.path.normpath(os.path.join(safe_root_dir, os.path.basename(user_supplied_path)))\nwith open(safe_path, 'r') as f:\n    data = f.read()"
                        else:
                            vuln.fix_suggestion = "// Prevent path traversal by using path.resolve and path.basename\nconst path = require('path');\nconst fs = require('fs');\nconst safePath = path.resolve(safeRootDir, path.basename(userSuppliedPath));\nconst data = fs.readFileSync(safePath, 'utf8');"
                    elif 'deserialization' in vuln.id.lower():
                        if vuln.file_path.endswith('.py'):
                            vuln.fix_suggestion = "# Use JSON instead of pickle for deserialization\nimport json\nobj = json.loads(user_data)"
                        else:
                            vuln.fix_suggestion = "// Use JSON.parse for safe deserialization\nconst obj = JSON.parse(userData);"
                    else:
                        logging.warning(f"Failed to generate fix for vulnerability in {vuln.file_path}:{vuln.line_number}")
            except Exception as e:
                logging.error(f"Error generating fix for vulnerability in {vuln.file_path}:{vuln.line_number}: {e}")

        return vulnerabilities

    def generate_fix_for_javascript(self, vulnerability: Vulnerability) -> Optional[str]:
        """Generates a fix specifically for JavaScript vulnerabilities.

        Args:
            vulnerability (Vulnerability): The vulnerability to generate a fix for.

        Returns:
            Optional[str]: The suggested fix, or None if no fix could be generated.
        """
        try:
            # Try to use our custom fix generators first
            custom_fix = get_fix_generator_for_vulnerability(vulnerability)
            if custom_fix:
                logging.info(f"Generated custom fix for {vulnerability.file_path}:{vulnerability.line_number}")
                return custom_fix

            # If not a SQL injection or custom generator failed, fall back to the AI model
            # Create a prompt that includes the vulnerability details and code
            # Tailor the prompt for JavaScript-specific vulnerabilities
            vuln_type = getattr(vulnerability, 'vulnerability_type', 'Unknown')
            code_snippet = getattr(vulnerability, 'code_snippet', vulnerability.code)

            prompt = f"""<s>[INST] You are an expert in JavaScript security. Fix the following vulnerability:

Vulnerability Type: {vuln_type}
Severity: {vulnerability.severity}
Description: {vulnerability.description}
File: {vulnerability.file_path}
Line: {vulnerability.line_number}

Vulnerable code:
```javascript
{code_snippet}
```

Provide only the fixed code without any explanation. The fix should address the security issue while maintaining the original functionality.
For SQL injection vulnerabilities, use parameterized queries with ? placeholders. [/INST]"""

            # Use the InferenceClient directly
            result = self.client.text_generation(
                prompt,
                model=self.model,
                max_new_tokens=500,
                temperature=0.2,
                do_sample=True
            )

            # Clean up the result (remove markdown code blocks if present)
            if "```" in result:
                # Extract code between the first and last code block markers
                start_idx = result.find("```") + 3
                # Skip the language identifier if present
                if result[start_idx:].startswith("javascript") or result[start_idx:].startswith("js"):
                    start_idx = result.find("\n", start_idx) + 1
                end_idx = result.rfind("```")
                if start_idx < end_idx:
                    result = result[start_idx:end_idx].strip()

            return result
        except Exception as e:
            logging.error(f"Error generating JavaScript fix: {e}")
            return None

    def generate_fixes_for_javascript_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Generates fixes for a list of JavaScript vulnerabilities.

        Args:
            vulnerabilities (List[Vulnerability]): The vulnerabilities to generate fixes for.

        Returns:
            List[Vulnerability]: The vulnerabilities with fix suggestions added.
        """
        for vuln in vulnerabilities:
            if vuln.file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
                try:
                    logging.info(f"Generating fix for JavaScript vulnerability in {vuln.file_path}:{vuln.line_number}")
                    fix = self.generate_fix_for_javascript(vuln)
                    if fix:
                        vuln.fix_suggestion = fix
                        logging.info(f"Successfully generated fix for JavaScript vulnerability in {vuln.file_path}:{vuln.line_number}")
                    else:
                        logging.warning(f"Failed to generate fix for JavaScript vulnerability in {vuln.file_path}:{vuln.line_number}")
                except Exception as e:
                    logging.error(f"Error generating fix for JavaScript vulnerability in {vuln.file_path}:{vuln.line_number}: {e}")

        return vulnerabilities
