<h1 align="center">TryHackMe - CTF Writeups</h1>

<p align="center">
  Walkthroughs of TryHackMe rooms, from recon to root, with the root cause at the
  code level and how to fix it.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rooms-5-C11B17?logo=tryhackme&logoColor=white" alt="rooms">
  <img src="https://img.shields.io/badge/hardest-Insane-8957E5" alt="hardest difficulty">
</p>

> Publication-safe: flag values and room-provided credentials are redacted, with the
> method and formats shown in full.

| Room | Difficulty | Category | Techniques |
|------|------------|----------|------------|
| [Cypheron](cypheron/) | Insane | AI / Red Team | ML pickle RCE (`torch.load`), static `.pt` analysis, n8n LFI (CVE-2026-21858), JWT forgery, container escape |
| [Operation Reroute](operation-reroute/) | Hard | Networking | BGP prefix hijack (longest-prefix-match), FRR/vtysh, DNS interception and exfiltration |
| [IronHold](ironhold/) | Hard | Web + Linux | Whitebox review, SQLi (UNION), mass assignment, Java deserialization (ysoserial) |
| [Frankesqwen](frankesqwen/) | Hard | AI Security | LLM weight memorization, guardrail bypass, model extraction by sampling |
| [Injectics](injectics/) | Medium | Web (PHP) | SQLi filter bypass, stacked queries (`DROP TABLE`), Twig SSTI to RCE (CVE-2022-23614) |
