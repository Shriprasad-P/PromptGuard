"""Prompt injection detection rules and scoring engine."""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Rule:
    """A single detection rule."""
    
    id: str
    pattern: str
    weight: int
    description: str
    channel: str = "both"  # "prompt", "tool_arg", or "both"


@dataclass
class MatchedRule:
    """A matched rule with context."""
    
    rule_id: str
    description: str
    weight: int
    matched_text: str


class RuleEngine:
    """Rule-based prompt injection detector."""
    
    def __init__(self):
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Rule]:
        """Load detection rules."""
        return [
            # High-risk instruction override patterns
            Rule(
                id="IGNORE_PREVIOUS",
                pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|commands?|prompts?|directives?)",
                weight=45,
                description="Instruction override attempt",
                channel="both"
            ),
            Rule(
                id="DISREGARD_INSTRUCTIONS",
                pattern=r"(disregard|forget|override|bypass)\s+(\w+\s+)?(previous|prior|your)\s+(instructions?|commands?|rules?)",
                weight=45,
                description="Disregard instructions attempt",
                channel="both"
            ),
            Rule(
                id="NEW_INSTRUCTIONS",
                pattern=r"(new|updated|revised|real)\s+(instructions?|commands?|directives?|rules?)\s*(are|:|begin)",
                weight=40,
                description="New instructions injection",
                channel="both"
            ),
            Rule(
                id="SYSTEM_PROMPT_LEAK",
                pattern=r"(show|reveal|display|print|tell\s+me|what\s+(is|are))\s+(your|the)\s+(system|original|initial)\s+(prompt|instructions?|rules?)",
                weight=50,
                description="System prompt leak attempt",
                channel="prompt"
            ),
            Rule(
                id="ROLE_OVERRIDE",
                pattern=r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?!a\s+coding|an?\s+assistant)",
                weight=40,
                description="Role override attempt",
                channel="prompt"
            ),
            Rule(
                id="DAN_JAILBREAK",
                pattern=r"\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted\s+mode)\b",
                weight=50,
                description="DAN/jailbreak pattern",
                channel="prompt"
            ),
            Rule(
                id="PROMPT_INJECTION_EXPLICIT",
                pattern=r"(this\s+is\s+a|attempt\s+a?)\s*(prompt\s+injection|injection\s+attack)",
                weight=70,
                description="Explicit injection reference",
                channel="both"
            ),
            
            # Encoding/obfuscation patterns
            Rule(
                id="BASE64_SUSPICIOUS",
                pattern=r"(base64|b64decode|atob)\s*\(.*\)|[A-Za-z0-9+/]{40,}={0,2}",
                weight=15,
                description="Possible encoded payload",
                channel="both"
            ),
            Rule(
                id="HEX_ENCODE",
                pattern=r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}",
                weight=15,
                description="Hex-encoded content",
                channel="both"
            ),
            Rule(
                id="UNICODE_ESCAPE",
                pattern=r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}",
                weight=15,
                description="Unicode escape sequences",
                channel="both"
            ),
            
            # Tool argument injection (shell/exfil)
            Rule(
                id="SHELL_EXFIL",
                pattern=r"(\|\s*(curl|wget|nc)\s+|\|\s*bash|\|\s*sh\b|>\s*/dev/|&\s*curl\s+|;\s*curl\s+|;\s*bash)",
                weight=70,
                description="Shell exfiltration pattern",
                channel="tool_arg"
            ),
            Rule(
                id="COMMAND_INJECTION",
                pattern=r"(`[^`]+`|\$\([^)]+\)|&&\s*(rm|cat|curl|wget|bash|sh)\b)",
                weight=60,
                description="Command injection attempt",
                channel="tool_arg"
            ),
            Rule(
                id="FILE_ACCESS",
                pattern=r"(/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.aws/credentials|\.env\b)",
                weight=50,
                description="Sensitive file access",
                channel="tool_arg"
            ),
            
            # Delimiter/boundary breaking
            Rule(
                id="DELIMITER_BREAK",
                pattern=r"(---|===|###)\s*(end|stop|ignore)\s+(system|assistant|instructions?)",
                weight=20,
                description="Delimiter boundary breaking",
                channel="both"
            ),
            Rule(
                id="BRACKET_ESCAPE",
                pattern=r"(\]\]>|</prompt>|</system>|\\end\{prompt\})",
                weight=20,
                description="Bracket escape attempt",
                channel="both"
            ),
            
            # Privilege escalation
            Rule(
                id="ADMIN_CLAIM",
                pattern=r"(i\s+am|you\s+must\s+treat\s+me\s+as)\s+(an?\s+)?(admin|root|superuser|administrator|god\s+mode)",
                weight=25,
                description="Privilege escalation claim",
                channel="prompt"
            ),
            Rule(
                id="SUDO_COMMAND",
                pattern=r"(sudo|su\s+-|doas)\s+",
                weight=20,
                description="Privilege escalation command",
                channel="tool_arg"
            ),
            
            # Output manipulation
            Rule(
                id="OUTPUT_OVERRIDE",
                pattern=r"(always|only|must)\s+(respond|reply|output|say|print)\s+with",
                weight=15,
                description="Output manipulation",
                channel="prompt"
            ),
            Rule(
                id="FORMAT_BREAK",
                pattern=r"(ignore|skip|bypass)\s+(the\s+)?(format|structure|template|schema)",
                weight=20,
                description="Format breaking attempt",
                channel="both"
            ),
        ]
    
    def check(self, text: str, channel: str = "prompt") -> tuple[int, List[MatchedRule]]:
        """
        Check text for injection patterns.
        
        Args:
            text: The text to check
            channel: "prompt" or "tool_arg"
            
        Returns:
            Tuple of (score, matched_rules)
        """
        matched = []
        
        for rule in self.rules:
            if rule.channel not in ("both", channel):
                continue
            
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            match = pattern.search(text)
            
            if match:
                matched_text = match.group(0)[:100]
                matched.append(MatchedRule(
                    rule_id=rule.id,
                    description=rule.description,
                    weight=rule.weight,
                    matched_text=matched_text
                ))
        
        score = min(100, sum(m.weight for m in matched))
        
        return score, matched


def get_decision(score: int, threshold: int) -> str:
    """
    Get decision based on score and threshold.
    
    Args:
        score: Detection score (0-100)
        threshold: Block threshold
        
    Returns:
        "allow", "review", or "block"
    """
    if score >= threshold:
        return "block"
    elif score >= 40:
        return "review"
    else:
        return "allow"
