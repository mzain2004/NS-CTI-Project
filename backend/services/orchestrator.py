from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Dict, Any, List
from pathlib import Path

from models.state import AgentState
from services.groq_service import get_groq_client

logger = logging.getLogger("orchestrator")

PLANNER_SYSTEM_PROMPT = """You are the Lead Threat Intelligence Orchestrator. Your task is to analyze a potential file/hash threat and decide on the next analysis step.
You have access to a set of analysis tools.

Available tools:
1. "static_analysis": Runs deep static analysis (YARA, PE structure, hashes, file type, extracted strings) on the target file.
   - Requires "file_path" and "filename" in context.
   - Result will populate "static_analysis" key in context.
2. "virustotal": Queries VirusTotal API to see if the hash is known as malware.
   - Requires "sha256" (which can be obtained after static_analysis or from context).
   - Result will populate "virustotal" key in context.
3. "dynamic_sandbox": Runs the target file in a simulated sandbox to watch process creation, C2 network connections, and registry writes.
   - Should be triggered when static analysis is suspicious, returned "Unclear", or we need runtime indicators.
   - Requires "file_path" in context.
   - Result will populate "dynamic_analysis" key in context.
4. "groq_forensics": Runs behavioral reasoning via an LLM on all gathered analysis to generate the final verdict, MITRE techniques, and risk level.
   - Requires "static_analysis" in context.
   - Result will populate "groq_analysis" key in context.
5. "active_defense": Blocks the malicious attacker IP on the network firewall.
   - Run this ONLY if a threat is confirmed with HIGH or CRITICAL risk, and we want to actively neutralize it.
   - Requires "attacker_ip" (which can be resolved automatically from Cowrie logs via the SHA256 context).
   - Result will populate "pfsense_block" key in context.
6. "complete": Finishes the orchestration run. Do this when you have successfully run the needed analysis pipeline and generated groq_forensics, or if active_defense has successfully completed when required.

Routing Instructions:
1. If "static_analysis_present" is false, you MUST choose "static_analysis".
2. If "static_analysis_verdict" is "Unclear" and "dynamic_analysis_present" is false, you MUST choose "dynamic_sandbox".
3. If "virustotal_present" is false, you SHOULD choose "virustotal".
4. If "groq_analysis_present" is false, you MUST choose "groq_forensics".
5. If "groq_analysis_present" is true:
   - If "risk_level" is "HIGH" or "CRITICAL" and "pfsense_block_present" is false, you MUST choose "active_defense".
   - Otherwise, you MUST choose "complete".

You must respond with ONLY a JSON object matching this schema:
{
  "reasoning": "Brief explanation of your decision based on history and context",
  "tool": "static_analysis | virustotal | dynamic_sandbox | groq_forensics | active_defense | complete"
}
"""

class Orchestrator:
    @staticmethod
    async def run(task: str, state: AgentState) -> AgentState:
        # Loop limit to prevent infinite loops
        max_steps = 10
        step_count = 0
        
        client = await get_groq_client()
        
        while not state.is_complete and step_count < max_steps:
            step_count += 1
            
            # 1. Build the history string
            history_str = "\n".join(state.history) if state.history else "No steps executed yet."
            
            # 2. Summarize context for the planner
            context_summary = {
                "file_path": state.context.get("file_path"),
                "filename": state.context.get("filename"),
                "sha256": state.context.get("sha256"),
                "static_analysis_present": "static_analysis" in state.context,
                "dynamic_analysis_present": "dynamic_analysis" in state.context,
                "virustotal_present": "virustotal" in state.context,
                "groq_analysis_present": "groq_analysis" in state.context,
                "pfsense_block_present": "pfsense_block" in state.context,
            }
            
            # Check if static_analysis indicates "Unclear"
            if "static_analysis" in state.context:
                static_data = state.context["static_analysis"]
                # Decide if packed or filename contains "unclear"
                is_unclear = "unclear" in state.context.get("filename", "").lower() or static_data.get("is_packed", False)
                context_summary["static_analysis_verdict"] = "Unclear" if is_unclear else "Clear"

            if "groq_analysis" in state.context:
                groq_data = state.context["groq_analysis"]
                context_summary["risk_level"] = groq_data.get("risk_level")
                if groq_data.get("risk_level") in ["HIGH", "CRITICAL"]:
                    state.current_risk_score = 0.9
                else:
                    state.current_risk_score = 0.3

            user_prompt = f"""
Current Task: {task}
Executed History:
{history_str}

Shared Memory / Context:
{json.dumps(context_summary, indent=2)}
"""

            # Call LLM Planner
            try:
                chat_completion = await client.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=[
                        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.0
                )
                response = chat_completion.choices[0].message.content.strip("`").strip()
                planner_res = json.loads(response)
                tool = planner_res.get("tool")
                reasoning = planner_res.get("reasoning", "")
                logger.info(f"Orchestrator Step {step_count} — Planner chose: {tool}. Reasoning: {reasoning}")
            except Exception as e:
                logger.error(f"Planner failed to select tool: {e}. Falling back to default sequence.")
                # Basic fallback sequence if LLM fails
                if "static_analysis" not in state.context:
                    tool = "static_analysis"
                elif "virustotal" not in state.context:
                    tool = "virustotal"
                elif "groq_analysis" not in state.context:
                    tool = "groq_forensics"
                elif "pfsense_block" not in state.context:
                    tool = "active_defense"
                else:
                    tool = "complete"
                reasoning = "Fallback due to LLM failure"

            # Execute selected tool
            if tool == "complete":
                state.is_complete = True
                state.history.append("Tool: complete")
                break
            
            tool_result = None
            try:
                if tool == "static_analysis":
                    from services import static_analysis
                    tool_result = await static_analysis.execute(state.context)
                elif tool == "virustotal":
                    from services import virustotal_service
                    tool_result = await virustotal_service.execute(state.context)
                elif tool == "dynamic_sandbox":
                    from services import dynamic_sandbox
                    tool_result = await dynamic_sandbox.execute(state.context)
                elif tool == "groq_forensics":
                    from services import groq_service
                    tool_result = await groq_service.execute(state.context)
                elif tool == "active_defense":
                    from services import pfsense_service
                    tool_result = await pfsense_service.execute(state.context)
                else:
                    logger.error(f"Unknown tool choice: {tool}")
                    state.history.append(f"Tool: {tool} failed (unknown tool)")
                    continue

                state.history.append(f"Tool: {tool} -> {reasoning}")
                if tool_result:
                    state.context.update(tool_result)
                    # Sync SHA256 if populated
                    if "static_analysis" in tool_result:
                        state.context["sha256"] = tool_result["static_analysis"].get("sha256")

            except Exception as exc:
                logger.error(f"Error executing tool {tool}: {exc}")
                state.history.append(f"Tool: {tool} failed with error: {exc}")

        return state
