# Terms of use and privacy

Haishin-ban (SafeRollout) — a safe rollout kit for Windows apps (free prototype).

This English text was translated with AI and has not been checked by a native speaker. If this English version and the Japanese version ([`利用条件.md`](利用条件.md)) differ, the Japanese version is the original.

## 1. What this tool does

You install and run this tool on your own PC or in-house server.

- The relay (`server.mjs`) receives start-up notices and crash reports from your apps, and refuses reports that appear to contain personal information or secrets.
- In the console you can see the crash rate per version and sign "halt" or "revoke" release manifests inside your own web browser.
- The C# components run inside your app: they verify release manifests, apply staged rollout, decide when to roll back to the previous version, and redact and send reports.

## 2. We do not collect or receive your data

- The tool sends nothing to the provider (HARVEST). Reports, settings, manifests, passwords and keys stay only on the PC or server where you run it. The provider cannot see them.
- You decide and manage how the reports received by the relay are stored, kept, deleted and accessed.
- The signing private key is created and used inside the console (your browser) and is never sent to the server. You are responsible for keeping key files, certificate keys and passwords safe.
- The source code is distributed via GitHub (a service of GitHub, Inc.). GitHub may keep connection records (such as IP addresses) of people who open its pages or download files, for security purposes. Please see GitHub's privacy statement. The provider does not view or use those records.

## 3. No guarantee

- This tool is a prototype and has not yet been deployed in a real production environment. Please try it on a test PC first.
- This tool does not find all personal information or secrets. In particular, it is known to miss names and addresses (see "Measured" in the README). Please also take care in your app, for example by not putting business data into exception messages.
- This tool is not a certification, accreditation or guarantee. It does not promise that update failures, defects or data loss will not happen. You are responsible for backups and checks before you distribute.
- The tool is provided "as is", free of charge.
- If the provider is liable for any damage you suffer from using, or being unable to use, this tool, the provider's total liability is limited to JPY 10,000.
- This cap applies only to damage caused by the provider's ordinary (slight) negligence. It does not apply to damage caused by the provider's willful misconduct or gross negligence.
- Nothing in these terms limits any rights you have under mandatory consumer-protection laws of your country or region.
- Whether your use meets the rules of your clients, parent company or business partners (information-security policies, handling of personal data) is for you and them to decide. This tool does not replace that decision.
- The tool does not give legal advice or make legal judgements (for example, about what privacy laws allow).

## 4. Permitted use

You may view the source code and use the tool within yourself or your own company free of charge, including for work. Copying and distributing, selling, distributing modified versions or incorporating it into other products requires prior written permission. See [`LICENSE`](LICENSE).

## 5. Provider

HARVEST (Japan) / Contact: garageten.info@gmail.com (this address dates from our former name, GARAGE TEN)

This tool is free.

## 6. Changes

We may change these terms. When we do, we will note the date in this document. Last updated: 15 November 2026
