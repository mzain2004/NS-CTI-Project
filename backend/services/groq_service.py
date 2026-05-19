from __future__ import annotations

import os
import json
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict

async def get_groq_client():
    """Lazy init — call this inside every function that needs client"""
    from groq import Groq
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    return Groq(api_key=os.getenv("GROQ_API_KEY"))

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
        File Name: {static_analysis['file_name']}
        File Size: {static_analysis['file_size']}
        File Type: {static_analysis['file_type']}
        Hashes: {static_analysis['hashes']}
        PE Sections: {static_analysis['pe_analysis']['sections']}
        Suspicious Imports: {static_analysis['pe_analysis']['imports'][:20]}
        YARA Hits: {static_analysis['yara_matches']}
        Extracted Strings: {static_analysis['strings'][:50]}
        Packed: {static_analysis['pe_analysis']['is_packed']}
        """

        # Initialize Groq client
        client = await get_groq_client()

        # Call Groq API
        response = await client.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt
        )

        # Parse JSON response
        try:
            return json.loads(response.strip("`"))
        except json.JSONDecodeError:
            # Retry once with clarification
            retry_response = await client.chat(
                system_prompt=system_prompt,
                user_prompt=user_prompt + "\nRespond with only JSON, no other text."
            )
            try:
                return json.loads(retry_response.strip("`"))
            except json.JSONDecodeError:
                return {"error": "parse_failed", "raw_response": retry_response}

    except Exception as e:
        return {"error": str(e)}
