# SHAI-HULUD V2 ATTACK CHECKER

This tool read a package-lock.json file, extracts all the packages and their versions and make two checks:

- Check if the installed package and version is in the known list of compromised packages, and will report those packages as vulnerabilities.
- Using `npm view <package_name>` under the hood, check when your packages were installed and compare with the known attack window (2025-05-24 until now). And will report those packages as potentially vulnerable.

## List of affected packages

Special thanks to Wiz Research for discovering and reporting this vulnerability and
keeping the community informed. The [report can be found here](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/shai-hulud-2-packages.csv).

## How the Attack Works

The malware uses stolen npm and GitHub tokens to republish legitimate packages with malicious code injected into install scripts (like preinstall hooks).

When you install or update such a package, the malicious script executes, potentially exfiltrating secrets, tokens, and other sensitive information from your machine or CI/CD environment.

## Usage

## What You Should Do

Run the tool against all your project's package-lock.json files

Immediately check if any packages you've installed or updated since the attack window are on the list of compromised packages or potentailly compromised.
If by any change you get a positive result, take the following actions:

Rotate all access tokens (GitHub, npm, cloud providers, etc.) that were stored on any affected machine, as these may have been stolen. Think that even agents/runner used in CI/CD pipelines could be compromised.

Clear your npm cache (npm cache clean --force), remove node_modules, and reinstall your dependencies to avoid reinfection.

Monitor for unusual activity in your accounts and repositories.
If you are not using package-lock.json, and you build your applications there's a high you are affected. Plese create a package-lock.json and pin all the package versions date to an inferior date to the attack window and once you've done it follow the steps above.

## Additional Security Measures

Use lock files (package-lock.json) to pin versions and avoid automatic updates to potentially compromised versions.
Regularly audit your dependencies and remove unused ones to minimize your attack surface
in CICD environemnts, consider the usage of the command

```bash
npm config set ignore-scripts true
```
