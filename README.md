# LLM-Based Intelligent Alert Triage

Source code and research artefacts for the master's thesis **"Reducing Alert Fatigue in SOCs: LLM-Based Intelligent Alert Triage"** — Tallinn University of Technology, 2026.

## Overview

This repository contains the implementation of a playbook-guided, multi-step LLM triage assistant designed to automate Tier-1 SOC analyst workflows. The system evaluates security alerts, invokes external enrichment tools and produces structured investigation notes with HP/LP classifications.

Two models were evaluated — GPT-5-mini and GPT-5-nano — across three operational modes: general, soft playbook-guided and strict playbook-guided.

## Repository Structure

```
alerts/                  Synthetic alert dataset (8 categories, 100 alerts)
chosen_alerts/           Alerts selected for the user study
exported_results/        Raw classification results per configuration
formatted_output/        Investigation notes converted to free-text format
logs_6/                  Execution logs for all six model/mode configurations
playbooks_soft/          Soft playbook definitions per alert category
playbooks_strict/        Strict playbook definitions per alert category
main.py                  Main triage pipeline entry point
mcp_server.py            MCP tool server (IP reputation, hash lookup, domain age, etc.)
scheduled_run.py         Batch evaluation runner across configurations
calculate_metrics.py     Computes metrics
calculate_tcr.py         Tool Compliance Rate calculation
file_extractor.py        Extracts and organises alert files for evaluation
json_to_text.py          Converts structured JSON investigation notes to free-text
domain_age.json          Local domain age database used by the domain age tool
users.json               Synthetic employee directory used by the user lookup tool
final_stats_report.json  Aggregated evaluation results across all configurations
```

## Requirements

```
python >= 3.10
openai
mcp
```

Install dependencies:

```bash
pip install openai mcp
```

## Usage

```bash
python main.py [--alert-folder FOLDER] [--strict | --soft | --general] [--model MODEL]
```

Set your OpenAI API key:

```bash
export OPENAI_API_KEY=your_key_here
```

Run the full batch evaluation:

```bash
python scheduled_run.py
```

## Operational Modes

| Mode | Description |
|------|-------------|
| `general` | No playbook guidance, model relies on system prompt and tool descriptions |
| `soft` | Playbook instructions written in standard directive language |
| `strict` | Playbook instructions written in capitalised, reinforced language with mandatory tool invocations |

## Author

Sanan Mammadli — TalTech, School of Information Technologies  
Supervisor: Ahmed Nasr