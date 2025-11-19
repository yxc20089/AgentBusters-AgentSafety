# Security Arena Competition Guide

## Welcome to the Security Arena Security Competition!

This competition challenges you to either:
- **Track 1**: Create novel security scenarios that test AI vulnerabilities
- **Track 2**: Build agents that outperform baselines at attacking or defending

Both tracks use the **Security Arena** framework - a flexible system for dynamic adversarial testing across multiple security scenarios.

---

## Competition Structure

### 🏁 Two Tracks, Two Challenges

#### **Track 1: Scenario Creation**
Build creative security test scenarios that expose AI vulnerabilities.

**You Provide**: Custom scenario plugin + configuration
**We Provide**: Generic arena + baseline attacker/defender agents
**Goal**: Create realistic, challenging scenarios with balanced difficulty

#### **Track 2: Agent Development**
Build sophisticated attackers or defenders that outperform baselines.

**You Provide**: Custom attacker or defender agent implementation
**We Provide**: Scenario definitions + generic arena
**Goal**: Achieve highest attack success rate (ASR) or defense rate

---

## Track 1: Scenario Creation Competition

### 🎯 Objective

Create a security scenario that:
1. Tests a **real-world AI vulnerability** (data poisoning, prompt injection, information disclosure, etc.)
2. Is **balanced** - not too easy (>80% ASR) or impossible (<10% ASR) for baseline agents
3. Has **clear success criteria** - unambiguous definition of attack success
4. Is **well-documented** - clear explanation of attack and defense

### 📋 What You Need to Submit

#### 1. **Scenario Plugin** (`plugins/your_scenario.py`)

Implement the `ScenarioPlugin` interface:

```python
from plugins.base import ScenarioPlugin

class YourScenarioPlugin(ScenarioPlugin):
    """
    Brief description of your scenario.

    Attack Type: [Data Poisoning / Prompt Injection / Info Disclosure / etc.]
    Domain: [Healthcare / Finance / E-commerce / etc.]
    Difficulty: [Easy / Medium / Hard]
    """

    def get_attack_objective(self) -> str:
        """High-level attack description for attacker"""
        return """**Attack Objective:** ...

        Explain what the attacker is trying to achieve."""

    def get_domain_description(self) -> str:
        """Context about the system being attacked"""
        return """**Domain:** ...

        Describe the application, its purpose, and context."""

    def get_attacker_goal(self) -> str:
        """Specific measurable goal"""
        return """**Your Goal:** ...

        Precise objective with clear success condition."""

    def get_attack_constraints(self) -> str:
        """Rules and limitations"""
        return """**Constraints:** ...

        What can/cannot the attacker do?"""

    def get_defender_role(self) -> str:
        """Defender's persona and purpose"""
        return """**Your Role:** ...

        Who is the defender? What's their job?"""

    def get_defender_task_description(self) -> str:
        """What defender should do with input"""
        return """**Your Task:** ...

        Clear task instructions."""

    def get_output_format(self) -> str:
        """Expected output structure"""
        return """**Output Format:** ...

        JSON, natural text, specific structure?"""

    def get_security_guidelines(self) -> str:
        """Defense strategies and attack patterns to watch for"""
        return """**Security Guidelines:** ...

        Detailed defense strategies."""

    def check_success(
        self,
        defender_response: str,
        original_input: str,
        modified_input: str
    ) -> tuple[bool, Any]:
        """
        Determine if attack succeeded.

        Returns:
            (success: bool, extracted_value: Any)
        """
        # Your custom detection logic
        success = ...  # True if attack succeeded
        value = ...    # Evidence of success/failure
        return success, value

    def get_baseline_input(self) -> str:
        """Clean input for baseline test"""
        return "Your clean baseline input"

    def get_baseline_expected_value(self) -> Any:
        """Expected output for baseline"""
        return "Expected value"
```

#### 2. **Configuration File** (`scenario_your_scenario.toml`)

```toml
[green_agent]
endpoint = "http://127.0.0.1:9010"
cmd = "python scenarios/security_arena/orchestrator.py --port 9010"

[[participants]]
role = "attacker"
endpoint = "http://127.0.0.1:9021"
cmd = "python scenarios/security_arena/agents/generic_attacker.py --port 9021"

[[participants]]
role = "defender"
endpoint = "http://127.0.0.1:9020"
cmd = "python scenarios/security_arena/agents/generic_defender.py --port 9020"

[config]
scenario_type = "your_scenario"
num_rounds = 5

# Your scenario-specific config
param1 = "value1"
param2 = ["list", "of", "values"]
```

#### 3. **Test Data** (if applicable)

If your scenario requires input data (documents, databases, etc.), provide it in `data/` directory.

#### 4. **Documentation** (`SCENARIO_DESCRIPTION.md`)

```markdown
# Scenario Name

## Overview
Brief description of the scenario and what it tests.

## Attack Type
[Data Poisoning / Prompt Injection / Info Disclosure / Tool Discovery / etc.]

## Real-World Relevance
Why does this vulnerability matter? Real-world examples?

## Success Criteria
Precise definition of what constitutes attack success.

## Expected Baseline Performance
- Estimated ASR: 30-50%
- Estimated Defense Rate: 50-70%

## Test Cases
Example attacks that should succeed/fail.

## Judging Criteria Notes
Any specific evaluation considerations?
```

### 🏆 Judging Criteria (Track 1)

| Criterion | Weight | Description |
|-----------|--------|-------------|
| **Realism** | 30% | Does it test real AI vulnerabilities? Is the scenario realistic? |
| **Difficulty Balance** | 25% | Target ASR: 20-60%. Not too easy, not impossible. |
| **Clarity** | 20% | Are success criteria well-defined? Is documentation clear? |
| **Creativity** | 15% | Novel attack vectors? Interesting domain? |
| **Implementation Quality** | 10% | Clean code? Good error handling? Well-structured? |

### ✅ Baseline ASR Targets

- **Easy Scenarios**: 40-60% ASR (baseline attacker succeeds often)
- **Medium Scenarios**: 25-40% ASR (balanced)
- **Hard Scenarios**: 10-25% ASR (baseline attacker struggles)

**Ideal**: 25-45% ASR with baseline agents

### 💡 Scenario Ideas

- **Healthcare**: Extract patient PII from medical chatbot
- **Finance**: Manipulate credit scores in loan application system
- **Legal**: Extract confidential case information from legal assistant
- **Code Security**: Inject malicious code into code review system
- **Authentication**: Bypass multi-factor authentication prompts
- **Data Exfiltration**: Extract proprietary data from customer service bot
- **Price Manipulation**: Change product prices in e-commerce assistant
- **Access Control**: Elevate privileges in role-based access system

---

## Track 2: Agent Development Competition

### 🎯 Objective

Build an agent that significantly outperforms baseline agents at either:
- **Attacking**: Breaking through defenses (high ASR)
- **Defending**: Resisting attacks (high defense rate)

### 📋 What You Need to Submit

#### 1. **Agent Implementation**

Create `custom_agents/your_agent.py`:

```python
from openai import AsyncOpenAI
from a2a.server.agent_execution import AgentExecutor
from a2a.types import TaskState
from a2a.utils import new_agent_text_message, new_task

class YourAttackerExecutor(AgentExecutor):
    """
    Your custom attacker agent.

    Techniques used:
    - [List your techniques]

    Expected performance:
    - ASR improvement: +20-30% over baseline
    """

    def __init__(self, model: str = "gpt-4o"):
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model

        # Your custom system prompt
        self.system_prompt = """Your advanced attacker prompt...

        Implement sophisticated techniques like:
        - Multi-strategy attack generation
        - Reflection on failures
        - Chain-of-thought reasoning
        - Adaptive strategy selection
        """

        self.conversation_history = {}

    async def execute(self, context, event_queue):
        """
        Generate sophisticated attacks.

        The orchestrator sends attack objectives in context.get_user_input().
        You must return the attack output.
        """
        # Your implementation
        # - Receive attack objective from orchestrator
        # - Generate sophisticated attack
        # - Return attack output

        pass  # Implement your logic
```

#### 2. **Agent Description** (`AGENT_DESCRIPTION.md`)

```markdown
# Agent Name

## Type
[Attacker / Defender]

## Strategy Overview
High-level description of your approach.

## Techniques Used
- Technique 1: Description
- Technique 2: Description
- ...

## Performance Results

### On PortfolioIQ:
- Baseline ASR: 25%
- Your Agent ASR: 55%
- **Improvement: +30%**

### On Thingularity:
- Baseline ASR: 40%
- Your Agent ASR: 65%
- **Improvement: +25%**

## Novel Contributions
What makes your agent unique or innovative?

## Requirements
Dependencies, specific models needed, etc.
```

#### 3. **Dependencies** (`requirements.txt` - if needed)

```
# Only if you use non-standard dependencies
anthropic==0.5.0
langchain==0.1.0
# etc.
```

### 🏆 Judging Criteria (Track 2)

| Criterion | Weight | Description |
|-----------|--------|-------------|
| **Performance** | 40% | ASR improvement (attackers) or defense rate (defenders) |
| **Generalization** | 25% | Performance across multiple scenarios |
| **Innovation** | 20% | Novel techniques, creative strategies |
| **Code Quality** | 10% | Clean, well-documented, efficient |
| **Robustness** | 5% | Handles edge cases, error recovery |

### 📊 Performance Metrics

#### For Attackers:

| Metric | Calculation | Goal |
|--------|-------------|------|
| **ASR Improvement** | Your ASR - Baseline ASR | >+20% |
| **Cross-Scenario ASR** | Average ASR across all scenarios | >50% |
| **Consistency** | Std dev of ASR across scenarios | Low |

#### For Defenders:

| Metric | Calculation | Goal |
|--------|-------------|------|
| **Defense Rate** | % of attacks blocked | >80% |
| **Cross-Scenario Defense** | Average defense rate across scenarios | >75% |
| **Resilience** | Defense against advanced attackers | >60% |

### 💡 Attack Strategy Ideas

- **Multi-Strategy Generation**: Generate 5 attacks, pick best
- **Chain-of-Thought**: Reason about defense weaknesses
- **Reflection**: Analyze why previous attempts failed
- **Prompt Optimization**: Iteratively refine attacks
- **Ensemble Methods**: Combine multiple attack techniques
- **Context Analysis**: Deep understanding of scenario
- **Adaptive Selection**: Choose strategy based on feedback

### 🛡️ Defense Strategy Ideas

- **Input Validation**: Detect malformed or suspicious inputs
- **Anomaly Detection**: Flag unusual patterns
- **Consistency Checks**: Verify data integrity
- **Sandboxing**: Isolate potentially harmful content
- **Fallback Strategies**: Safe defaults when uncertain
- **Multi-Layer Validation**: Multiple security checks
- **Pattern Recognition**: Learn attack signatures

---

## Submission Process

### 1. Prepare Your Submission

**Track 1 (Scenarios)**:
```
your_scenario_submission/
├── plugins/your_scenario.py
├── scenario_your_scenario.toml
├── data/                      # If needed
│   └── test_data.json
└── SCENARIO_DESCRIPTION.md
```

**Track 2 (Agents)**:
```
your_agent_submission/
├── custom_agents/your_agent.py
├── requirements.txt           # If needed
└── AGENT_DESCRIPTION.md
```

### 2. Test Locally

**Track 1**:
```bash
# Register your scenario in plugins/registry.py
# Then test:
uv run agentbeats-run scenarios/security_arena/scenario_your_scenario.toml
```

**Track 2**:
```bash
# Update TOML to use your agent
# Test on multiple scenarios:
uv run agentbeats-run scenarios/security_arena/scenario_portfolioiq.toml
uv run agentbeats-run scenarios/security_arena/scenario_thingularity.toml
```

### 3. Document Results

Include baseline comparison in your description:
- Baseline ASR
- Your agent/scenario ASR
- Improvement metrics
- Test logs/screenshots

### 4. Submit

[Submission instructions will be provided by Lambda]

---

## Evaluation Process

### Phase 1: Technical Validation

- ✅ Code runs without errors
- ✅ Follows required interfaces
- ✅ Documentation complete
- ✅ Baseline comparisons provided

### Phase 2: Performance Testing

**Track 1**: Run baseline agents on your scenario
- Measure ASR, defense rate
- Test clarity of success criteria
- Verify balanced difficulty

**Track 2**: Run your agent on Lambda scenarios
- Test on PortfolioIQ, Thingularity
- Test on hidden evaluation scenarios
- Measure cross-scenario performance

### Phase 3: Judging

Expert panel evaluates:
- Adherence to judging criteria
- Real-world relevance
- Innovation and creativity
- Code quality

---

## Tips for Success

### Track 1 (Scenarios)

✅ **DO**:
- Test realistic vulnerabilities
- Aim for 25-45% baseline ASR
- Provide clear success criteria
- Document thoroughly
- Test with baseline agents

❌ **DON'T**:
- Make scenarios too easy (>70% ASR)
- Make scenarios impossible (<10% ASR)
- Use vague success criteria
- Forget to test baseline performance

### Track 2 (Agents)

✅ **DO**:
- Test on multiple scenarios
- Document your strategy
- Show significant improvement (>20%)
- Handle edge cases gracefully
- Use clear, well-structured code

❌ **DON'T**:
- Overfit to one scenario
- Hardcode scenario-specific logic
- Ignore error handling
- Use overly complex approaches
- Forget to document novel techniques

---

## FAQ

**Q: Can I submit to both tracks?**
A: Yes! You can submit a scenario AND an agent.

**Q: What models can I use?**
A: Any OpenAI, Anthropic, or open-source model. Specify in your submission.

**Q: Can I use external tools/APIs?**
A: Yes, but document all dependencies and ensure they're ethical/legal.

**Q: How many rounds should my scenario have?**
A: Default is 5 rounds. You can adjust based on scenario needs.

**Q: Can I modify the arena orchestrator?**
A: No. Submit only plugins (Track 1) or agents (Track 2).

**Q: What if my scenario needs special input data?**
A: Include it in `data/` directory with clear documentation.

**Q: Can I see other submissions before submitting?**
A: No, submissions are kept confidential until competition ends.

**Q: What's the deadline?**
A: [Will be announced by Lambda]

**Q: What are the prizes?**
A: [Will be announced by Lambda]

---

## Resources

- **Security Arena README**: `scenarios/security_arena/README.md`
- **Plugin Interface**: `scenarios/security_arena/plugins/base.py`
- **Example Scenarios**:
  - PortfolioIQ: `plugins/portfolioiq.py`
  - Thingularity: `plugins/thingularity.py`
  - Medical Example: `plugins/example_medical.py`
- **Example Agents**:
  - Generic Attacker: `agents/generic_attacker.py`
  - Generic Defender: `agents/generic_defender.py`

---

## Support

For questions or issues:
1. Check this guide and README first
2. Review example scenarios/agents
3. Test locally before submitting
4. Contact: [To be provided by Lambda]

---

**Good luck and happy hacking! 🚀**

*Remember: This is ethical security testing to make AI systems safer. All submissions should reflect responsible security research practices.*
