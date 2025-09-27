
# Implementation Plan: Improved Test Design for ZeroSSL Plugin

**Branch**: `002-the-original-test` | **Date**: 2025-09-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/002-the-original-test/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path
   → If not found: ERROR "No feature spec at {path}"
2. Fill Technical Context (scan for NEEDS CLARIFICATION)
   → Detect Project Type from context (web=frontend+backend, mobile=app+api)
   → Set Structure Decision based on project type
3. Fill the Constitution Check section based on the content of the constitution document.
4. Evaluate Constitution Check section below
   → If violations exist: Document in Complexity Tracking
   → If no justification possible: ERROR "Simplify approach first"
   → Update Progress Tracking: Initial Constitution Check
5. Execute Phase 0 → research.md
   → If NEEDS CLARIFICATION remain: ERROR "Resolve unknowns"
6. Execute Phase 1 → contracts, data-model.md, quickstart.md, agent-specific template file (e.g., `CLAUDE.md` for Claude Code, `.github/copilot-instructions.md` for GitHub Copilot, `GEMINI.md` for Gemini CLI, `QWEN.md` for Qwen Code or `AGENTS.md` for opencode).
7. Re-evaluate Constitution Check section
   → If new violations: Refactor design, return to Phase 1
   → Update Progress Tracking: Post-Design Constitution Check
8. Plan Phase 2 → Describe task generation approach (DO NOT create tasks.md)
9. STOP - Ready for /tasks command
```

**IMPORTANT**: The /plan command STOPS at step 7. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary
Redesign unit and component tests to improve reliability by mocking only at HTTP boundaries, using real method signatures, and achieving 80% line coverage with 30-second execution time. Focus on testing actual code paths rather than over-mocking internal logic to catch real bugs instead of test design issues.

## Technical Context
**Language/Version**: Python 3.12+
**Primary Dependencies**: ansible>=8.0.0, requests>=2.31.0, cryptography>=41.0.0
**Storage**: File system (certificates, CSRs, validation files)
**Testing**: pytest>=7.4.0, pytest-ansible>=4.0.0, pytest-mock>=3.11.0, coverage>=7.3.0
**Target Platform**: Linux/macOS (Ansible control nodes)
**Project Type**: single - Ansible plugin with modular architecture
**Performance Goals**: 80% line coverage, <30 second test execution time
**Constraints**: using current project tech stack, don't introduce any new library, mock only at HTTP boundary
**Scale/Scope**: ~25 test files covering unit/component tests for ZeroSSL certificate lifecycle

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Initial Constitution Check**: PASS
- ✅ No new libraries introduced (constraint met)
- ✅ Uses existing test framework (pytest with current dependencies)
- ✅ Test-first approach maintained (redesigning tests to be more effective)
- ✅ Focuses on existing functionality improvement, not new features
- ✅ Preserves current project architecture and dependencies

**Post-Design Constitution Check**: PASS
- ✅ Design maintains existing tech stack (pytest, requests-mock)
- ✅ Test contracts follow TDD principles (tests define behavior)
- ✅ No additional dependencies introduced in Phase 1 design
- ✅ Coverage and performance contracts are measurable
- ✅ Architecture preserves existing plugin structure

## Project Structure

### Documentation (this feature)
```
specs/[###-feature]/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
# Option 1: Single project (DEFAULT)
src/
├── models/
├── services/
├── cli/
└── lib/

tests/
├── contract/
├── integration/
└── unit/

# Option 2: Web application (when "frontend" + "backend" detected)
backend/
├── src/
│   ├── models/
│   ├── services/
│   └── api/
└── tests/

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   └── services/
└── tests/

# Option 3: Mobile + API (when "iOS/Android" detected)
api/
└── [same as backend above]

ios/ or android/
└── [platform-specific structure]
```

**Structure Decision**: Option 1 (Single project) - Ansible plugin with existing modular structure (plugins/, tests/)

## Phase 0: Outline & Research
1. **Extract unknowns from Technical Context** above:
   - For each NEEDS CLARIFICATION → research task
   - For each dependency → best practices task
   - For each integration → patterns task

2. **Generate and dispatch research agents**:
   ```
   For each unknown in Technical Context:
     Task: "Research {unknown} for {feature context}"
   For each technology choice:
     Task: "Find best practices for {tech} in {domain}"
   ```

3. **Consolidate findings** in `research.md` using format:
   - Decision: [what was chosen]
   - Rationale: [why chosen]
   - Alternatives considered: [what else evaluated]

**Output**: research.md with all NEEDS CLARIFICATION resolved

## Phase 1: Design & Contracts
*Prerequisites: research.md complete*

1. **Extract entities from feature spec** → `data-model.md`:
   - Entity name, fields, relationships
   - Validation rules from requirements
   - State transitions if applicable

2. **Generate API contracts** from functional requirements:
   - For each user action → endpoint
   - Use standard REST/GraphQL patterns
   - Output OpenAPI/GraphQL schema to `/contracts/`

3. **Generate contract tests** from contracts:
   - One test file per endpoint
   - Assert request/response schemas
   - Tests must fail (no implementation yet)

4. **Extract test scenarios** from user stories:
   - Each story → integration test scenario
   - Quickstart test = story validation steps

5. **Update agent file incrementally** (O(1) operation):
   - Run `.specify/scripts/bash/update-agent-context.sh claude`
     **IMPORTANT**: Execute it exactly as specified above. Do not add or remove any arguments.
   - If exists: Add only NEW tech from current plan
   - Preserve manual additions between markers
   - Update recent changes (keep last 3)
   - Keep under 150 lines for token efficiency
   - Output to repository root

**Output**: data-model.md, /contracts/*, failing tests, quickstart.md, agent-specific file

## Phase 2: Task Planning Approach
*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:
- Load `.specify/templates/tasks-template.md` as base
- Generate tasks from test contracts and data model
- Each test module in tests/unit/ → redesign task [P]
- Each test module in tests/component/ → redesign task [P]
- Coverage measurement setup → infrastructure task
- Performance validation → verification task
- Documentation updates → maintenance task

**Ordering Strategy**:
- TDD order: Infrastructure setup first, then test redesign
- Dependency order: Fixtures before individual tests before suites
- Mark [P] for parallel execution (independent test files)
- Sequential dependencies: coverage setup → test implementation → validation

**Task Categories**:
1. **Infrastructure Tasks**: Update conftest.py, create realistic fixtures
2. **Test Redesign Tasks**: Convert each existing test file to improved design
3. **Coverage Tasks**: Implement coverage measurement and reporting
4. **Validation Tasks**: Verify performance and quality requirements
5. **Documentation Tasks**: Update test documentation and guidelines

**Estimated Output**: 15-20 numbered, ordered tasks in tasks.md

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation
*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)
**Phase 4**: Implementation (execute tasks.md following constitutional principles)
**Phase 5**: Validation (run tests, execute quickstart.md, performance validation)

## Complexity Tracking
*Fill ONLY if Constitution Check has violations that must be justified*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |


## Progress Tracking
*This checklist is updated during execution flow*

**Phase Status**:
- [x] Phase 0: Research complete (/plan command)
- [x] Phase 1: Design complete (/plan command)
- [x] Phase 2: Task planning complete (/plan command - describe approach only)
- [x] Phase 3: Tasks generated (/tasks command)
- [x] Phase 4.1: Setup Infrastructure implementation complete (T001-T004)
- [ ] Phase 4.2: Contract Tests implementation (T005-T007)
- [ ] Phase 4.3: Test Redesign implementation (T008-T028)
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: PASS
- [x] Post-Design Constitution Check: PASS
- [x] All NEEDS CLARIFICATION resolved
- [x] Complexity deviations documented

---
*Based on Constitution v2.1.1 - See `/memory/constitution.md`*
