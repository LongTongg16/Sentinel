# Development Workflow

## Standard Flow
1. Pull latest main: `git checkout main && git pull origin main`
2. Create a branch: `git checkout -b feature/name-of-feature`
3. Make changes and commit: `git add . && git commit -m "feat: short description"`
4. Push branch: `git push origin feature/name-of-feature`
5. Open a Pull Request on GitHub
6. Self-review using the Code Review Checklist below before merging
7. Merge using Squash and merge
8. Sync local main: `git checkout main && git pull origin main`

## Branch Naming
- feature/name
- fix/name
- docs/name
- test/name
- ci/name
- chore/name

## Commit Message Examples
- feat: add SSL/TLS certificate check
- fix: handle unreachable host timeout
- test: add scoring function unit tests
- docs: add local setup guide
- ci: add backend pytest workflow

## Rules
- Never push directly to main
- Use Pull Requests for all changes, even solo — it keeps history clean and gives you a self-review checkpoint
- Keep PRs small and focused

## Code Review Checklist
- [ ] Code is understandable
- [ ] Logic matches the issue requirements
- [ ] No obvious bugs or edge cases missed
- [ ] No unrelated changes
- [ ] Error handling is reasonable
- [ ] Tests are included or not needed
- [ ] UI changes are visually checked
- [ ] API changes are documented or compatible
- [ ] Security-sensitive changes are reviewed carefully
