from __future__ import annotations

import os
import json
from pathlib import Path
from dotenv import load_dotenv

async def get_groq_client():
    """Lazy init — call this inside every function that needs client"""
    from groq import AsyncGroq
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    return AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))

async def analyze_with_groq(static_analysis: dict) -> dict:
    """
    Takes static_analysis dict (from static_analysis service).
    Builds prompt, calls Groq, parses JSON response.
    Returns GroqAnalysis-shaped dict.
    """
    try:
        # Build the system prompt
        system_prompt = (
            "You are an expert malware analyst with 15 years of experience in reverse engineering,\n"
            "threat intelligence, and incident response. You analyze static analysis artifacts from\n"
            "potentially malicious files and produce structured threat intelligence reports.\n\n"
            "You MUST respond with ONLY valid JSON — no markdown, no explanation, no preamble.\n"
            "The JSON must match this exact schema:\n"
            "{\n"
            "  \"malware_family\": \"string — best guess family name or 'Unknown'\",\n"
            "  \"confidence\": integer 0-100,\n"
            "  \"behavior_summary\": \"2-3 paragraph detailed behavioral analysis\",\n"
            "  \"mitre_techniques\": [\n"
            "    {\n"
            "      \"technique_id\": \"T####\",\n"
            "      \"technique_name\": \"string\",\n"
            "      \"tactic\": \"string\",\n"
            "      \"description\": \"why this technique is indicated by the artifacts\",\n"
            "      \"confidence\": integer 0-100\n"
            "    }\n"
            "  ],\n"
            "  \"iocs\": {\n"
            "    \"ips\": [\"string\"],\n"
            "    \"domains\": [\"string\"],\n"
            "    \"urls\": [\"string\"],\n"
            "    \"hashes\": [\"string\"],\n"
            "    \"registry_keys\": [\"string\"],\n"
            "    \"file_paths\": [\"string\"],\n"
            "    \"mutexes\": [\"string\"]\n"
            "  },\n"
            "  \"risk_level\": \"LOW|MEDIUM|HIGH|CRITICAL\",\n"
            "  \"recommended_actions\": [\"string — specific actionable recommendation\"],\n"
            "  \"analyst_notes\": \"string — additional context, caveats, limitations of this analysis\"\n"
            "}\n"
        )

        # Construct the user prompt
        user_prompt = f"""
        File Name: {static_analysis.get('file_name')}
        File Size: {static_analysis.get('file_size')}
        File Type: {static_analysis.get('file_type')}
        MD5: {static_analysis.get('md5')}
        SHA256: {static_analysis.get('sha256')}
        PE Sections: {static_analysis.get('pe_sections')}
        Suspicious Imports: {static_analysis.get('imports', [])[:20]}
        YARA Hits: {static_analysis.get('yara_hits')}
        Extracted Strings: {static_analysis.get('strings_extracted', [])[:50]}
        Packed: {static_analysis.get('is_packed')}
        """

        # Initialize Groq client
        client = await get_groq_client()

        # Call Groq API
        chat_completion = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0
        )
        response = chat_completion.choices[0].message.content

        # Parse JSON response
        try:
            result = json.loads(response.strip("`").strip())
        except json.JSONDecodeError:
            # Retry once with clarification
            retry_completion = await client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt + "\nRespond with only JSON, no other text."}
                ],
                temperature=0.0
            )
            retry_response = retry_completion.choices[0].message.content
            try:
                result = json.loads(retry_response.strip("`").strip())
            except json.JSONDecodeError:
                result = {"error": "parse_failed", "raw_response": retry_response}

        # Save to disk for report service
        sha256 = static_analysis.get('sha256')
        if sha256:
            output_path = Path("/tmp/samples") / sha256 / "groq.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w") as f:
                json.dump(result, f, indent=4)

        return result

    except Exception as e:
        return {"error": str(e)}


async def execute(context: dict) -> dict:
    static_analysis = context.get("static_analysis")
    if not static_analysis:
        return {"error": "Missing static_analysis in context for Groq behavioral analysis"}
    
    dynamic_analysis = context.get("dynamic_analysis")
    if dynamic_analysis:
        static_analysis = dict(static_analysis)
        static_analysis["dynamic_sandbox_results"] = dynamic_analysis
        
    result = await analyze_with_groq(static_analysis)
    return {"groq_analysis": result}
