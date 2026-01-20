# Make sure you're in the right place
cd ~/Documents/entra-attack-path-visualizer

# Initialize git
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit - Entra ID Attack Path Visualizer with Microsoft Graph integration, automated admin detection, and visual privilege path analysis"

# Add remote
git remote add origin https://github.com/Dfrank77/entra-attack-path-visualizer.git

# Set branch to main
git branch -M main

# Push
git push -u origin main

# FIRST TIME SETUP (Do Once Per Machine)

# Set your name (shows in commits)
git config --global user.name "Darius Frank"

# Set your email (must match GitHub email)
git config --global user.email "your-email@example.com"

# Check your settings
git config --list

# STARTING A NEW PROJECT

# Navigate to your project folder
cd ~/Documents/my-project

# Initialize git
git init

# Add all files to staging
git add .

# Make first commit
git commit -m "Initial commit"

# Create repo on GitHub first (via website)
# Then connect local to GitHub:
git remote add origin https://github.com/YourUsername/repo-name.git

# Set branch to main
git branch -M main

# Push to GitHub
git push -u origin main

# DAILY WORKFLOW (Making Changes)
# Check what changed
bash 
git status

# See what's different in files
git diff

# Add specific file
git add filename.py

# Add all changed files
git add .

# Commit with message
git commit -m "Fix bug in login function"

# Push to GitHub
git push

# Or if first time on new branch:
git push -u origin branch-name

# PULLING UPDATES FROM GITHUB
# Get latest changes from GitHub
git pull

# Or more explicit:
git pull origin main

# CHECKING HISTORY
# See commit history
git log

# See last 5 commits
git log -5

# See compact history
git log --oneline

# See who changed what in a file
git blame filename.py

# BRANCHES (Working on Features) 
# See all branches
git branch

# Create new branch
git branch feature-name

# Switch to branch
git checkout feature-name

# Create AND switch to new branch (shortcut)
git checkout -b feature-name

# Push branch to GitHub
git push -u origin feature-name

# Switch back to main
git checkout main

# Delete local branch
git branch -d feature-name

# Delete remote branch on GitHub
git push origin --delete feature-name

# UNDOING MISTAKES
# Unstage file (undo git add)
git reset filename.py

# Discard changes in file (DANGEROUS - can't undo!)
git checkout -- filename.py

# Undo last commit (keep changes)
git reset --soft HEAD~1

# Undo last commit (discard changes)
git reset --hard HEAD~1

# Undo git push (DANGEROUS - avoid if others pulled)
git push --force

# REMOVING FILES
# Remove file from git AND filesystem
git rm filename.py

# Remove file from git ONLY (keep locally)
git rm --cached filename.py

# Remove entire folder from git only
git rm --cached -r folder-name/

# Commit the removal
git commit -m "Remove old files"

# Push
git push

# GITIGNORE (Ignore Files)
# Create .gitignore file
touch .gitignore

# Add patterns to ignore
echo "*.log" >> .gitignore
echo "venv/" >> .gitignore
echo ".env" >> .gitignore
echo "__pycache__/" >> .gitignore

# Commit gitignore
git add .gitignore
git commit -m "Add gitignore"
git push

# WORKING WITH REMOTES
# See remote repos
git remote -v

# Add remote
git remote add origin https://github.com/user/repo.git

# Change remote URL
git remote set-url origin https://github.com/user/new-repo.git

# Remove remote
git remote remove origin

# COMMON FIXES
Fix: "fatal: not a git repository"
# You're not in a git folder, navigate there:
cd ~/Documents/your-project

# Or initialize git:
git init

Fix: "Your branch is ahead of 'origin/main'"
# You made commits but didn't push
git push

Fix: "Your branch is behind 'origin/main'"
# GitHub has changes you don't have
git pull

Fix: Can't push - "Updates were rejected"
# Someone else pushed first, pull their changes:
git pull
# Fix any conflicts if needed, then:
git push

Fix: Accidentally committed wrong file
# Remove from staging but keep changes
git reset HEAD filename.py

# Or remove from last commit
git reset --soft HEAD~1
# Then re-add only what you want:
git add correct-file.py
git commit -m "Correct commit"

# TYPICAL WORKFLOW EXAMPLE
# Morning: Get latest code
git pull

# Work on feature
# ... make changes to files ...

# Check what changed
git status

# Stage changes
git add .

# Commit
git commit -m "Add user authentication feature"

# Push to GitHub
git push

# End of day, check everything is pushed
git status

# QUICK REFERENCE
Command                     What It Does
git status                  See what changed
git add .                   Stage all changes
git commit -m  "message"    Save changes with message
git push                    Upload to GitHub
git pull                    Download from GitHub
git clone URL               Download repo
git log                     See history
git branch                  See branchesgit checkout -b 
                            nameCreate new branch                          