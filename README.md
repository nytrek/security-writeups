<h1 align="center">Security Writeups</h1>

<p align="center">
  Source-level security writeups and working exploits from CTF rooms and
  deliberately vulnerable labs.<br>
  Each one covers the root cause in the code, how I exploited it, and how to fix it.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TryHackMe-5_CTF_writeups-C11B17?logo=tryhackme&logoColor=white" alt="TryHackMe writeups">
  <img src="https://img.shields.io/badge/DVWA-local_lab-0A7E07" alt="DVWA lab">
  <img src="https://img.shields.io/badge/focus-web_%7C_AI_%7C_network-1F6FEB" alt="Focus">
</p>

---

## TryHackMe - CTF writeups

Publication-safe: flag values and room-provided credentials are redacted, with the
method and formats shown in full.

| Room | Difficulty | Techniques |
|------|------------|------------|
| [Cypheron](tryhackme/cypheron/) | Insane | ML pickle RCE (`torch.load`), n8n LFI (CVE-2026-21858), JWT forgery, container escape |
| [Operation Reroute](tryhackme/operation-reroute/) | Hard | BGP prefix hijack (longest-prefix-match), FRR routing, DNS interception and exfil |
| [IronHold](tryhackme/ironhold/) | Hard | Whitebox: SQLi (UNION), mass assignment, Java deserialization (ysoserial) |
| [Frankesqwen](tryhackme/frankesqwen/) | Hard | AI security: LLM weight memorization, guardrail bypass, model extraction |
| [Injectics](tryhackme/injectics/) | Medium | SQLi filter bypass, stacked queries, Twig SSTI to RCE (CVE-2022-23614) |

## DVWA - local lab

Deliberately vulnerable app running on my own network, worked level by level. One
folder per vulnerability. Lab setup (OS, versions, how to reach it):
[dvwa/00-setup](dvwa/00-setup/).

| # | Module | Levels | Status |
|---|--------|--------|--------|
| 01 | [Brute Force](dvwa/01-brute-force/) | low | done |
| 02 | Command Injection | - | planned |
| 03 | SQL Injection | - | planned |
| 04 | File Upload | - | planned |
| 05 | XSS (Reflected / Stored) | - | planned |
| 06 | CSRF | - | planned |

## Scope and legal

Everything here targets lab environments I run myself or platforms that permit
publishing writeups. Do not run any of this against systems you don't own or don't
have written permission to test.
