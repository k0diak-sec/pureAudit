# PureAudit — Setup Guide
## Get this on GitHub in 5 minutes

### Step 1: Create the repo on GitHub
```bash
# Open terminal and navigate to where you want the project
cd ~/Desktop   # or wherever you keep projects

# Create the repo using GitHub CLI
gh repo create pureAudit --public --description "Home network security auditing tool by PureSecure" --clone
cd pureAudit
```

### Step 2: Copy the project files in
Copy all the files from the downloaded pureAudit folder into this new directory.
Or if you downloaded it to Downloads:
```bash
cp -r ~/Downloads/pureAudit/* ~/Desktop/pureAudit/
cp ~/Downloads/pureAudit/.gitignore ~/Desktop/pureAudit/
```

### Step 3: Install dependencies & run tests
```bash
pip install -r requirements.txt
python -m unittest tests/testPortScanner.py -v
```

### Step 4: First commit — make it count
```bash
git add .
git commit -m "Initial commit: PureAudit project scaffolding with network scanner, port scanner, vulnerability flagging, and report generator"
git push origin main
```

### Step 5: Daily commits start NOW
Here's your commit plan for the rest of the week:

**Day 2:** Improve networkScanner.py — add vendor lookup for MAC addresses
**Day 3:** Add more test cases in tests/ — testNetworkScanner.py
**Day 4:** Enhance reportGenerator.py — add color-coded severity in TXT report
**Day 5:** Add a new module: serviceDetector.py — banner grabbing for open ports
**Day 6:** CLI enhancements — add --verbose and --quiet flags
**Day 7:** Add testReportGenerator.py and update README with screenshots

### Running PureAudit
```bash
# Quick scan (discover devices on your network)
sudo python src/main.py --scan

# Full audit with report
sudo python src/main.py --audit

# Scan a specific subnet
sudo python src/main.py --target 192.168.1.0/24 --audit
```
Note: `sudo` is needed for ARP scanning. The fallback mode works without it.
